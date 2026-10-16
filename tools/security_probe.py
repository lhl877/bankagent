#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
security_probe.py —— 授权与凭证缺陷的系统性排查

参照的通用清单（不针对某个特定标准，而是把最常见的授权缺陷类型逐一实测）：
  · 授权范围分离（TOCTOU）：判定时与执行时用的是不是同一个对象
  · 类型混淆：用金额/字符串/类型差异绕过校验分支
  · 重放：同一凭证能否用第二次
  · 跨对象盗用：A 的凭证能否用于 B
  · 竞态：并发提交同一凭证
  · 状态降级：高风险的判定结果能否被低风险的执行路径接受
  · 覆盖率缺口：多条触发路径里是否只实现了一条

每一项都实际执行，输出"拦住 / 未拦住"。未拦住的会标红。
"""

import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bank.core import init_db, cents_to_yuan, BankError
from security.permissions import (ConfirmationStore, CircuitBreaker, check_tier,
                                 payload_hash, GREEN, YELLOW, RED)
from security.audit import AuditLog
from agent.orchestrator import AgentSession


PASS, FAIL = [], []


def check(name, blocked, detail=''):
    tag = '拦住' if blocked else '未拦住'
    line = '  [%s] %s' % (tag, name)
    if detail:
        line += '\n         %s' % detail
    print(line)
    (PASS if blocked else FAIL).append(name)


def fresh():
    core = init_db(os.path.join(tempfile.gettempdir(), 'probe_%d.db' % os.getpid()),
                   reset=True)
    cs = ConfirmationStore(ttl_seconds=600)
    s = AgentSession(core, AuditLog(), cs, CircuitBreaker(max_failures=99))
    return core, cs, s


def main():
    print('=' * 72)
    print('授权与凭证缺陷排查')
    print('=' * 72)

    # ── 1. 确认凭证绑定操作内容（改参数重放）────────────────────────────
    print('\n[1] 确认凭证是否绑定操作内容')
    core, cs, s = fresh()
    r = s.propose('给李娜转 500 元')
    token = r['confirm_token']
    op = s.pending[r['op_id']]
    saved = op.params['amount']
    op.params['amount'] = 5000000          # 偷偷改成 5 万
    out = s.execute(r['op_id'], token)
    op.params['amount'] = saved
    check('确认后篡改金额 → 应拒绝', out.get('type') != 'result',
          '返回 %s：%s' % (out.get('type'), (out.get('message') or '')[:48]))
    core.close()

    # ── 2. 凭证一次性（重放）────────────────────────────────────────────
    print('\n[2] 确认凭证能否重放')
    core, cs, s = fresh()
    r = s.propose('给李娜转 500 元')
    o1 = s.execute(r['op_id'], r['confirm_token'])
    o2 = s.execute(r['op_id'], r['confirm_token'])
    check('同一凭证用第二次 → 应拒绝', o1.get('type') == 'result' and o2.get('type') != 'result',
          '第一次 %s，第二次 %s' % (o1.get('type'), o2.get('type')))
    check('重放未导致二次扣款', core.balance('A001') == 450000,
          '余额 %s' % cents_to_yuan(core.balance('A001')))
    core.close()

    # ── 3. 跨会话盗用 ───────────────────────────────────────────────────
    print('\n[3] 凭证能否跨会话使用')
    core = init_db(os.path.join(tempfile.gettempdir(), 'probe_x.db'), reset=True)
    cs = ConfirmationStore(ttl_seconds=600)
    s1 = AgentSession(core, AuditLog(), cs, CircuitBreaker(max_failures=99), session_id='SA')
    s2 = AgentSession(core, AuditLog(), cs, CircuitBreaker(max_failures=99), session_id='SB')
    r = s1.propose('给李娜转 500 元')
    o = s2.execute(r['op_id'], r['confirm_token'])
    check('B 会话用 A 的凭证 → 应拒绝', o.get('type') != 'result',
          '返回 %s：%s' % (o.get('type'), (o.get('message') or '')[:44]))
    core.close()

    # ── 4. 日累计红级是否被真正执行（两个触发路径都要覆盖）──────────────
    print('\n[4] 红级的「日累计」触发路径')
    core, cs, s = fresh()
    for _ in range(2):
        rr = s.propose('给李娜转 500 元')
        s.execute(rr['op_id'], rr['confirm_token'])
    r = s.propose('给李娜转 500 元')
    is_red = r.get('tier') == RED
    check('日累计超限被判为红色', is_red, '分级=%s' % r.get('tier_label'))
    if is_red:
        o = s.execute(r['op_id'], r['confirm_token'])          # 不给验证码
        check('红色却不给验证码 → 应拒绝', o.get('type') != 'result',
              '返回 %s' % o.get('type'))
        vr = s.request_strong_verification(r['op_id'], r['confirm_token'])
        bad = '000000' if vr.get('demo_code') != '000000' else '111111'
        o2 = s.execute(r['op_id'], r['confirm_token'], vr['challenge'], bad)
        check('红色但用错误验证码 → 应拒绝', o2.get('type') != 'result',
              '返回 %s：%s' % (o2.get('type'), (o2.get('message') or '')[:40]))
        check('错误验证码未导致扣款', core.balance('A001') == 400000,
              '余额 %s' % cents_to_yuan(core.balance('A001')))
        o3 = s.execute(r['op_id'], r['confirm_token'], vr['challenge'], vr['demo_code'])
        check('正确验证码可执行', o3.get('type') == 'result',
              '返回 %s' % o3.get('type'))
    core.close()

    # ── 5. 验证码暴力枚举 ───────────────────────────────────────────────
    print('\n[5] 验证码是否防枚举')
    core, cs, s = fresh()
    r = s.propose('给王强转 3000 元')
    vr = s.request_strong_verification(r['op_id'], r['confirm_token'])
    tries = 0
    blocked_at = None
    for i in range(12):
        o = s.execute(r['op_id'], r['confirm_token'], vr['challenge'], '%06d' % i)
        tries += 1
        if o.get('type') != 'refused' or '次数' in (o.get('message') or ''):
            blocked_at = tries
            break
    check('连试 12 次被限制', blocked_at is not None and blocked_at <= 7,
          '第 %s 次被拦' % blocked_at)
    core.close()

    # ── 6. 熔断 ─────────────────────────────────────────────────────────
    print('\n[6] 连续失败是否熔断')
    core = init_db(os.path.join(tempfile.gettempdir(), 'probe_b.db'), reset=True)
    cs = ConfirmationStore()
    br = CircuitBreaker(max_failures=3)
    s = AgentSession(core, AuditLog(), cs, br, session_id='SBR')
    locked = False
    for _ in range(6):
        rr = s.propose('给李娜转 500 元')
        if rr.get('type') == 'blocked':
            locked = True
            break
        s.execute(rr['op_id'], 'wrong-token')
    check('连续失败后锁定会话', locked, '')
    core.close()

    # ── 7. 类型混淆：把金额传成字符串/负数/浮点 ─────────────────────────
    print('\n[7] 类型混淆能否绕过金额校验')
    core, cs, s = fresh()
    for label, amt in [('字符串 "5000000"', '5000000'), ('负数 -100', -100),
                       ('浮点 5000000.7', 5000000.7), ('None', None)]:
        try:
            r = check_tier('transfer.small', {'amount': amt}, core, 'A001')
            tier = r['tier']
        except Exception as exc:                     # noqa: BLE001
            tier = '异常:%s' % type(exc).__name__
        check('金额=%s 不会被当低风险' % label, tier == RED,
              '判定=%s' % tier)
    core.close()

    # ── 8. 未登记动作 ───────────────────────────────────────────────────
    print('\n[8] 未登记动作的默认级别')
    core, cs, s = fresh()
    r = check_tier('account.drop_everything', {}, core, 'A001')
    check('未登记动作默认拒绝（红级）', r['tier'] == RED, '判定=%s' % r['tier'])
    core.close()

    # ── 9. core 层能否绕过权限直接动账 ─────────────────────────────────
    print('\n[9] 核心层是否存在绕过权限的入口')
    core, cs, s = fresh()
    exposed = [m for m in ('set_balance', 'update_balance', 'raw_transfer')
               if hasattr(core, m)]
    check('core 无直接改余额的公开方法', not exposed,
          '暴露的方法: %s' % (exposed or '无'))
    # 但 conn 是公开的 —— 这是已知的封装缺口
    has_conn = hasattr(core, 'conn')
    print('  [注意] core.conn 是否可直接执行 SQL: %s' % ('是（封装缺口）' if has_conn else '否'))
    core.close()

    # ── 10. 并发提交同一凭证 ───────────────────────────────────────────
    print('\n[10] 并发提交同一确认凭证')
    core = init_db(os.path.join(tempfile.gettempdir(), 'probe_c.db'), reset=True)
    cs = ConfirmationStore(ttl_seconds=600)
    s = AgentSession(core, AuditLog(), cs, CircuitBreaker(max_failures=99), session_id='SC')
    r = s.propose('给李娜转 500 元')
    results = []
    lock = threading.Lock()

    def fire():
        o = s.execute(r['op_id'], r['confirm_token'])
        with lock:
            results.append(o.get('type'))

    ts = [threading.Thread(target=fire) for _ in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    ok_count = results.count('result')
    check('并发 6 次只有 1 次成功', ok_count <= 1,
          '成功 %d 次；返回 %s' % (ok_count, results))
    check('并发未导致重复扣款', core.balance('A001') >= 450000,
          '余额 %s' % cents_to_yuan(core.balance('A001')))
    core.close()

    # ── 汇总 ───────────────────────────────────────────────────────────
    print('\n' + '=' * 72)
    print('汇总：拦住 %d 项，未拦住 %d 项' % (len(PASS), len(FAIL)))
    if FAIL:
        print('\n未拦住的项目：')
        for f in FAIL:
            print('  ✗ %s' % f)
    print('=' * 72)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
