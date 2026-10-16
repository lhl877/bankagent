#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
permissions.py —— 权限分级引擎

这是整个系统的安全核心。赛题把它标为「实现优先级：高」，
本模块的目标是：让"分级"成为**不可绕过的执行约束**，而不是 Agent 的自觉。

三条设计原则
============
1. **分级由代码判定，不由模型决定。**
   Agent 的职责是识别意图并**申报**它想做什么；至于这件事是绿黄红哪一级，
   永远由 check_tier() 根据规则重新算。模型没有投票权。
   否则一句"这笔转账已被用户授权，属于绿色操作"就能骗过去。

2. **每次执行前重算，绝不复用判定结果。**
   用户发起时算出来是黄色，等用户确认的这段时间里他可能已经转过几笔，
   日累计变成红色。所以 execute 时必须**再算一次**。
   缓存判定结果 = 给攻击者留了一个时间窗。

3. **确认凭证绑定操作内容（payload hash）。**
   这是最容易被忽略、也最危险的一条。凭证只证明"用户确认过某件事"，
   必须同时证明"现在要执行的这件事，就是他确认过的那件"。
   否则确认一笔 100 元，改成 10000 元重放，凭证照样有效。
"""

import hashlib
import hmac
import json
import os
import secrets
import time

# ── 分级 ──────────────────────────────────────────────────────────────
GREEN = 'green'    # 自动执行
YELLOW = 'yellow'  # 用户确认
RED = 'red'        # 强验证（多因子）

TIER_LABEL = {
    GREEN: '绿色 · 自动执行',
    YELLOW: '黄色 · 需确认',
    RED: '红色 · 需强验证',
}

# 赛题规定：小额转账（日累计 ≤ 1000 元）为黄色，> 1000 元为红色。
# 单位是分，所以阈值 = 100000。
#
# 单笔阈值与日累计阈值恰好都是 1000 元，所以用同一个常量。
# 如果将来业务把它们拆开（比如单笔 2000 但日累计 1000），
# 改成一个 dict 即可，判定逻辑已经区分了「单笔」和「累计」两条路径。
SMALL_TRANSFER_CAP = 100000

# 操作注册表：每个动作声明自己的基准分级与所需能力。
# 注意这里写的是**基准**，实际分级还要结合参数（金额、日累计）动态调整。
ACTIONS = {
    # ── 绿色：纯查询，无副作用 ──────────────────────────────────────
    'account.balance':      {'tier': GREEN, 'desc': '查询余额',       'sensitive': False},
    'account.list':         {'tier': GREEN, 'desc': '查询账户列表',   'sensitive': False},
    'account.find_contact': {'tier': GREEN, 'desc': '按姓名/手机号查找收款人', 'sensitive': False},
    'tx.list':              {'tier': GREEN, 'desc': '查询交易记录',   'sensitive': False},
    'bill.analyze':         {'tier': GREEN, 'desc': '账单分析',       'sensitive': False},
    'bill.anomaly':         {'tier': GREEN, 'desc': '异常交易识别',   'sensitive': False},
    'wealth.list':          {'tier': GREEN, 'desc': '查询理财产品',   'sensitive': False},
    'wealth.holdings':      {'tier': GREEN, 'desc': '查询持仓与收益', 'sensitive': False},
    'subscription.list':    {'tier': GREEN, 'desc': '查询订阅与代扣', 'sensitive': False},

    # ── 黄色：有副作用但可逆、金额小 ────────────────────────────────
    'transfer.small':       {'tier': YELLOW, 'desc': '小额转账',      'sensitive': True},
    'transfer.scheduled':   {'tier': YELLOW, 'desc': '定时转账',      'sensitive': True},
    'split.request':        {'tier': YELLOW, 'desc': '发起 AA 收款',  'sensitive': True},
    'subscription.cancel':  {'tier': YELLOW, 'desc': '取消订阅',      'sensitive': True},
    'card.apply_virtual':   {'tier': YELLOW, 'desc': '申请虚拟卡',    'sensitive': True},

    # ── 红色：不可逆、或涉及资金安全 ────────────────────────────────
    'transfer.large':       {'tier': RED, 'desc': '大额转账',         'sensitive': True},
    'wealth.purchase':      {'tier': RED, 'desc': '申购理财产品',     'sensitive': True},
    'wealth.redeem':        {'tier': RED, 'desc': '赎回理财产品',     'sensitive': True},
    'card.limit_change':    {'tier': RED, 'desc': '调整卡额度',       'sensitive': True},
    'card.freeze':          {'tier': RED, 'desc': '挂失/冻结卡片',    'sensitive': True},
    'card.unfreeze':        {'tier': RED, 'desc': '卡片解挂',         'sensitive': True},
    'password.change':      {'tier': RED, 'desc': '修改密码',         'sensitive': True},
    'card.unlock_limit':    {'tier': RED, 'desc': '解除交易限制',     'sensitive': True},
}

# 未知动作：默认拒绝，且按最高级别处理。
# 「默认拒绝」是安全设计的常识，但很多 demo 会写反 —— 没登记的动作用绿色放行。
DEFAULT_TIER = RED


# ── payload 规范化与哈希 ──────────────────────────────────────────────
def payload_hash(action, params):
    """把「动作 + 参数」规范化成一个稳定的哈希。

    确认凭证绑在它上面，所以两件事必须成立：
      · 相同内容 → 相同哈希（否则用户正常确认也会失败）
      · 内容不同 → 哈希必然不同（否则可以改参数重放）

    做法：按键名排序后序列化，排除与内容无关的字段（如时间戳、随机数）。
    """
    clean = {k: v for k, v in (params or {}).items()
             if k not in ('idem_key', 'confirmed_at', 'nonce', 'ts')}
    canonical = json.dumps({'action': action, 'params': clean},
                           sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


# ── 分级判定 ──────────────────────────────────────────────────────────
def check_tier(action, params, core, acct_id):
    """判定一次操作的级别。**纯函数**，不写任何状态。

    返回 dict:
      { tier, action, desc, reasons[], needs[], dynamic }

    reasons 是给用户看的"为什么是这一级"，答辩时可以直接展示判定依据。
    """
    spec = ACTIONS.get(action)
    if not spec:
        return {
            'tier': DEFAULT_TIER,
            'action': action,
            'desc': '未登记的动作',
            'reasons': ['该动作不在允许的操作清单内，按最高风险处理（默认拒绝原则）'],
            'needs': ['strong_verification'],
            'dynamic': False,
        }

    tier = spec['tier']
    reasons = ['%s 的基准级别：%s' % (spec['desc'], TIER_LABEL[tier])]
    dynamic = False

    # ── 动态升级规则：转账按金额抬级 ────────────────────────────────
    if action in ('transfer.small', 'transfer.large', 'transfer.scheduled'):
        amount = int(params.get('amount') or 0)
        dynamic = True

        if amount <= 0:
            # 金额还没定，先按当前基准；执行前会重算
            reasons.append('金额尚未确定')
        elif amount > SMALL_TRANSFER_CAP:
            tier = RED
            reasons.append('单笔 %s 元 > %s 元，超出小额上限 → 升为红色'
                           % (fmt(amount), fmt(SMALL_TRANSFER_CAP)))
        else:
            # 关键：看**日累计**，不只看单笔。
            # 否则可以把 2000 元拆成 3 笔 700 元，笔笔都是黄色，绕开强验证。
            used = core.daily_outgoing(acct_id) if (core and acct_id) else 0
            projected = used + amount
            if projected > SMALL_TRANSFER_CAP:
                tier = RED
                reasons.append('今日已转出 %s 元，加上本笔将达 %s 元，超出小额上限 %s 元 → 升为红色'
                               % (fmt(used), fmt(projected), fmt(SMALL_TRANSFER_CAP)))
            else:
                tier = YELLOW
                reasons.append('今日已转出 %s 元，本笔后累计 %s 元，在小额上限 %s 元内'
                               % (fmt(used), fmt(projected), fmt(SMALL_TRANSFER_CAP)))

    needs = {
        GREEN: [],
        YELLOW: ['user_confirmation'],
        RED: ['user_confirmation', 'strong_verification'],
    }[tier]

    return {
        'tier': tier,
        'action': action,
        'desc': spec['desc'],
        'reasons': reasons,
        'needs': needs,
        'dynamic': dynamic,
    }


def fmt(cents):
    return '%.2f' % (int(cents) / 100.0)


# ── 确认凭证：绑定操作内容，带时效，一次性 ────────────────────────────
class ConfirmationStore:
    """确认凭证的存储。

    设计要点：
      · **绑定 payload_hash** —— 凭证只对"那一次具体的操作"有效
      · **一次性** —— 用过即作废，不能重放
      · **短时效** —— 默认 120 秒，超时需重新确认
      · **绑定会话** —— 别的会话拿到 token 也用不了

    进程内存储即可：演示系统单进程运行。
    真实系统要放 Redis 之类的共享存储（多实例部署时需要），
    并且要用 HMAC 签名而不是只存内存里的随机串。
    """

    def __init__(self, ttl_seconds=120):
        self.ttl = ttl_seconds
        self._store = {}          # token -> record
        # 强验证码用固定 key 签名，服务端可复算，不依赖会话状态
        self._otp_secret = secrets.token_bytes(32)
        self._otp = {}            # challenge_id -> record

    # ── 普通确认（黄级用；红级也先要它）────────────────────────────
    def issue(self, session_id, action, params):
        token = secrets.token_urlsafe(24)
        self._store[token] = {
            'session': session_id,
            'action': action,
            'payload_hash': payload_hash(action, params),
            'issued_at': time.time(),
            'used': False,
        }
        self._prune()
        return token

    def peek(self, token, session_id, action, params):
        """只校验，**不消费**。用于"还要先过强验证"的场景。

        为什么需要它：红级操作要同时过「确认凭证」和「短信验证码」。
        如果先消费确认凭证、再验验证码，那么用户验证码输错一次，
        确认凭证就废了 —— 必须从头重来。
        更糟的是：这等于让攻击者能用错误的验证码**把用户锁死**（拒绝服务）。

        所以拆成两步：peek 查资格 → 全部通过后 consume 才作废。
        """
        rec = self._store.get(token)
        if not rec:
            return False, '确认凭证不存在或已失效'
        if rec['used']:
            return False, '该确认凭证已被使用过（防重放）'
        if rec['session'] != session_id:
            return False, '确认凭证不属于当前会话'
        if time.time() - rec['issued_at'] > self.ttl:
            self._store.pop(token, None)
            return False, '确认已超时（%d 秒），请重新确认' % self.ttl
        if rec['action'] != action:
            return False, '确认的操作与当前要执行的操作不一致'
        if not hmac.compare_digest(rec['payload_hash'], payload_hash(action, params)):
            return False, '操作内容与确认时不一致（参数被改动），已拒绝'
        return True, 'ok'

    def consume(self, token):
        """把凭证标记为已用。只在**全部校验都通过、即将执行**时调用。"""
        rec = self._store.get(token)
        if rec:
            rec['used'] = True

    def verify_and_consume(self, token, session_id, action, params):
        """校验并**立即作废**。返回 (ok, reason)。

        适用于只需确认、不需强验证的黄级操作。
        红级请用 peek() + consume()，避免验证码输错就作废凭证。
        """
        ok, why = self.peek(token, session_id, action, params)
        if not ok:
            return False, why
        self.consume(token)
        return True, 'ok'

    # ── 强验证（红级用）────────────────────────────────────────────
    def issue_otp(self, session_id, action, params):
        """生成一次性验证码。演示环境直接返回明文码，真实环境只发短信。"""
        challenge_id = secrets.token_urlsafe(12)
        code = '%06d' % secrets.randbelow(1000000)
        self._otp[challenge_id] = {
            'session': session_id,
            'action': action,
            'payload_hash': payload_hash(action, params),
            'code_mac': hmac.new(self._otp_secret, code.encode(), hashlib.sha256).hexdigest(),
            'issued_at': time.time(),
            'tries': 0,
            'used': False,
        }
        return challenge_id, code

    def verify_otp(self, challenge_id, session_id, action, params, code):
        rec = self._otp.get(challenge_id)
        if not rec:
            return False, '验证码已失效，请重新获取'
        if rec['used']:
            return False, '该验证码已被使用过'
        if rec['session'] != session_id:
            return False, '验证码不属于当前会话'
        if time.time() - rec['issued_at'] > self.ttl:
            self._otp.pop(challenge_id, None)
            return False, '验证码已超时（%d 秒）' % self.ttl

        # 防暴力枚举：同一 challenge 最多试 5 次
        rec['tries'] += 1
        if rec['tries'] > 5:
            self._otp.pop(challenge_id, None)
            return False, '尝试次数过多，验证码已作废'

        if rec['action'] != action:
            return False, '验证码对应的操作不一致'
        if not hmac.compare_digest(rec['payload_hash'], payload_hash(action, params)):
            return False, '操作内容与获取验证码时不一致（参数被改动）'

        want = hmac.new(self._otp_secret, str(code).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(rec['code_mac'], want):
            return False, '验证码不正确'

        rec['used'] = True
        return True, 'ok'

    def _prune(self):
        now = time.time()
        for k in [k for k, v in self._store.items() if now - v['issued_at'] > self.ttl * 4]:
            self._store.pop(k, None)
        for k in [k for k, v in self._otp.items() if now - v['issued_at'] > self.ttl * 4]:
            self._otp.pop(k, None)


# ── 熔断器 ────────────────────────────────────────────────────────────
class CircuitBreaker:
    """连续失败 / 可疑行为触发锁定。

    赛题要求「异常熔断」。这里的判定标准是：
      · 同一会话在窗口内累计失败 N 次 → 锁定该会话
      · 窗口内出现「参数被篡改」这类**主动攻击特征** → 立即锁定

    区分"用户手滑"和"有人在攻击"很重要：
    前者应该允许重试，后者应该直接断掉。
    """

    def __init__(self, max_failures=3, window_seconds=300, lock_seconds=600):
        self.max_failures = max_failures
        self.window = window_seconds
        self.lock_seconds = lock_seconds
        self._fail = {}      # session -> [timestamps]
        self._locked = {}    # session -> unlock_at
        self._events = []    # 审计用

    def locked(self, session_id):
        until = self._locked.get(session_id)
        if until and time.time() < until:
            return True, until - time.time()
        if until:
            self._locked.pop(session_id, None)
        return False, 0

    def record_failure(self, session_id, kind='failure'):
        now = time.time()
        lst = [t for t in self._fail.get(session_id, []) if now - t < self.window]
        lst.append(now)
        self._fail[session_id] = lst

        # 主动攻击特征：直接锁，不给重试机会
        if kind == 'tamper':
            self._locked[session_id] = now + self.lock_seconds
            self._events.append({'at': now, 'session': session_id,
                                 'event': 'LOCKED', 'reason': '检测到参数篡改'})
            return True, '检测到确认凭证与操作内容不一致，出于安全考虑已临时锁定，请稍后重试或联系客服'

        if len(lst) >= self.max_failures:
            self._locked[session_id] = now + self.lock_seconds
            self._events.append({'at': now, 'session': session_id,
                                 'event': 'LOCKED',
                                 'reason': '窗口内失败 %d 次' % len(lst)})
            return True, '连续失败 %d 次，已临时锁定 %d 分钟' % (len(lst), self.lock_seconds // 60)

        left = self.max_failures - len(lst)
        return False, '还可重试 %d 次' % left

    def record_success(self, session_id):
        self._fail.pop(session_id, None)

    def events(self):
        return list(self._events)


if __name__ == '__main__':
    print('=== 权限分级引擎自测 ===')
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from bank.core import init_db, yuan_to_cents
    import tempfile

    core = init_db(os.path.join(tempfile.gettempdir(), 'bank_perm_test.db'))

    print('\n[1] 分级判定：查询类应为绿色')
    for a, p in [('account.balance', {'acct': 'A001'}),
                 ('bill.analyze', {'acct': 'A001', 'period': 'month'})]:
        r = check_tier(a, p, core, 'A001')
        print('    %-22s → %-18s' % (a, TIER_LABEL[r['tier']]))

    print('\n[2] 金额驱动抬级：500 元 vs 2000 元')
    r1 = check_tier('transfer.small', {'amount': yuan_to_cents(500)}, core, 'A001')
    r2 = check_tier('transfer.small', {'amount': yuan_to_cents(2000)}, core, 'A001')
    print('    500 元  → %s' % TIER_LABEL[r1['tier']])
    print('              %s' % r1['reasons'][-1])
    print('    2000 元 → %s' % TIER_LABEL[r2['tier']])
    print('              %s' % r2['reasons'][-1])

    print('\n[3] 拆分绕过：日累计才是关键')
    # 先真实转出 600 元（需确认，这里直接调核心模拟已批准的执行）
    core.transfer('A001', 'A002', yuan_to_cents(600), 'perm-test-1')
    r3 = check_tier('transfer.small', {'amount': yuan_to_cents(600)}, core, 'A001')
    print('    今日已转 600 元，再转 600 元 → %s' % TIER_LABEL[r3['tier']])
    print('    %s' % r3['reasons'][-1])
    print('    （若只看单笔，两笔都是黄色，可绕开强验证 —— 所以必须看累计）')

    print('\n[4] 未登记动作 → 默认拒绝')
    r4 = check_tier('account.delete_everything', {}, core, 'A001')
    print('    %s  %s' % (TIER_LABEL[r4['tier']], r4['reasons'][0]))

    print('\n[5] 确认凭证绑定操作内容')
    cs = ConfirmationStore()
    params_ok = {'from': 'A001', 'to': 'A002', 'amount': yuan_to_cents(100)}
    tok = cs.issue('sess-1', 'transfer.small', params_ok)
    ok, why = cs.verify_and_consume(tok, 'sess-1', 'transfer.small', params_ok)
    print('    原参数执行: %s (%s)' % (ok, why))

    tok2 = cs.issue('sess-1', 'transfer.small', params_ok)
    tampered = {'from': 'A001', 'to': 'A002', 'amount': yuan_to_cents(10000)}
    ok2, why2 = cs.verify_and_consume(tok2, 'sess-1', 'transfer.small', tampered)
    print('    改大金额重放: %s (%s)' % (ok2, why2))

    print('\n[6] 凭证一次性')
    tok3 = cs.issue('sess-1', 'transfer.small', params_ok)
    a1, _ = cs.verify_and_consume(tok3, 'sess-1', 'transfer.small', params_ok)
    a2, w2 = cs.verify_and_consume(tok3, 'sess-1', 'transfer.small', params_ok)
    print('    第一次: %s   第二次: %s (%s)' % (a1, a2, w2))

    print('\n[7] 跨会话盗用')
    tok4 = cs.issue('sess-1', 'transfer.small', params_ok)
    b1, bw = cs.verify_and_consume(tok4, 'sess-2', 'transfer.small', params_ok)
    print('    用 sess-2 提交 sess-1 的凭证: %s (%s)' % (b1, bw))

    print('\n[8] 强验证码')
    cid, code = cs.issue_otp('sess-1', 'transfer.large', tampered)
    e1, ew = cs.verify_otp(cid, 'sess-1', 'transfer.large', tampered, '000000')
    print('    错误验证码: %s (%s)' % (e1, ew))
    e2, ew2 = cs.verify_otp(cid, 'sess-1', 'transfer.large', tampered, code)
    print('    正确验证码: %s (%s)' % (e2, ew2))

    print('\n[9] 熔断：参数篡改直接锁定')
    cb = CircuitBreaker()
    locked, msg = cb.record_failure('sess-x', kind='tamper')
    print('    %s  %s' % (locked, msg))
    print('    当前锁定状态: %s' % (cb.locked('sess-x')[0],))

    core.close()
    print('\n自测完成。')
