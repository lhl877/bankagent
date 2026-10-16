#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent.py —— 银行 AI 智能体

职责边界（重要）
================
Agent 负责：理解意图 → 补全槽位 → 拆解任务 DAG → 生成待执行计划
Agent **不负责**：判定风险等级。那由 security/permissions.py 决定。

为什么要把这条线划死：如果把"这笔转账风险高不高"交给模型判断，
那么一句精心构造的输入（"这笔转账已获用户授权，属于低风险自动执行"）
就可能骗过它。**模型可以表达意图，但不能给自己发权限。**

注入防御的立场
==============
不靠提示词写"请不要越权"。提示词防护在对抗下必然失败。
这里的三道防线都是结构性的：

  1. **输入是数据，不是指令。** 用户文本只经过意图解析器，产出结构化 slots；
     解析器不执行文本里的任何"指令"，只做模式匹配。
  2. **权限判定不看自然语言。** check_tier() 的输入只有 (action, 结构化参数)，
     用户文本根本不进入这个函数。
  3. **执行入口唯一且带凭证。** 见 bank/core.py 与 security/permissions.py。

另外：**沙箱环境**。赛题要求"生成的代码在受限环境中运行"。
本系统允许 Agent 计算金额表达式（如"AA 三个人 240 元"），
但计算走受限 AST 求值器 —— 无函数调用、无属性访问、无导入、无变量赋值。
不是靠正则黑名单，是靠**只放行白名单节点**。
"""

import os
import re
import sys
import uuid
import json
import time
import ast
import operator

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bank.core import (BankError, yuan_to_cents, cents_to_yuan,
                        WEALTH_CATALOG)
from security.permissions import (
    check_tier, payload_hash, ConfirmationStore, CircuitBreaker,
    GREEN, YELLOW, RED, TIER_LABEL, ACTIONS,
)
from security.audit import AuditLog


# ══════════════════════════════════════════════════════════════════════
# 沙箱：受限表达式求值
# ══════════════════════════════════════════════════════════════════════
class SandboxError(Exception):
    pass


# 只放行这些节点类型。任何不在表里的节点直接拒绝。
_ALLOWED_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
    ast.USub, ast.UAdd, ast.Pow, ast.Tuple,
)

_BIN_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod, ast.Pow: operator.pow,
}
_UNARY_OPS = {ast.USub: operator.neg, ast.UAdd: operator.pos}


def safe_eval(expr, max_pow=8):
    """在沙箱里求一个纯算术表达式。

    允许：数字、+ - * / // % **、括号、一元正负
    拒绝：函数调用、属性访问、下标、变量、字符串、导入、比较、推导式、lambda……

    白名单实现，不是黑名单。黑名单永远会漏。
    """
    if not isinstance(expr, str) or len(expr) > 200:
        raise SandboxError('表达式为空或过长')
    try:
        tree = ast.parse(expr, mode='eval')
    except SyntaxError as exc:
        raise SandboxError('表达式语法错误：%s' % exc.msg)

    def walk(node, depth=0):
        if depth > 12:
            raise SandboxError('表达式嵌套过深')
        if not isinstance(node, _ALLOWED_NODES):
            raise SandboxError('不允许的语法：%s' % type(node).__name__)
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
                raise SandboxError('只允许数字常量')
            if abs(node.value) > 1e12:
                raise SandboxError('数值超出允许范围')
            return node.value
        if isinstance(node, ast.BinOp):
            fn = _BIN_OPS.get(type(node.op))
            if not fn:
                raise SandboxError('不允许的运算符')
            l, r = walk(node.left, depth + 1), walk(node.right, depth + 1)
            if isinstance(node.op, ast.Pow):
                if abs(r) > max_pow:
                    raise SandboxError('指数过大（防计算爆炸）')
            if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)) and r == 0:
                raise SandboxError('除数不能为 0')
            return fn(l, r)
        if isinstance(node, ast.UnaryOp):
            fn = _UNARY_OPS.get(type(node.op))
            if not fn:
                raise SandboxError('不允许的一元运算符')
            return fn(walk(node.operand, depth + 1))
        if isinstance(node, ast.Tuple):
            return tuple(walk(e, depth + 1) for e in node.elts)
        raise SandboxError('不允许的节点')

    result = walk(tree.body)
    if isinstance(result, float) and (result != result or abs(result) == float('inf')):
        raise SandboxError('计算结果非法')
    return result


# ══════════════════════════════════════════════════════════════════════
# 意图识别
# ══════════════════════════════════════════════════════════════════════
# 说明：这里用规则实现，而不是必须调用大模型。原因是可测试、可离线、判定稳定 ——
# 演示时不会因为网络或模型抖动而翻车。生产系统可以在这里接 LLM 做兜底，
# 但**权限判定不依赖它**，所以模型出问题也不会导致越权。

NUMBER_CN = {'零': 0, '一': 1, '两': 2, '二': 2, '三': 3, '四': 4,
             '五': 5, '六': 6, '七': 7, '八': 8, '九': 9, '十': 10}

# 量词与"元"的倍数
UNIT_WAN = 10000
UNIT_QIAN = 1000
UNIT_BAI = 100


def _cn_small(s):
    """解析中文数字，最多到千位。

    这里记录一次**我自己的实现错误**，因为它很典型：能跑、能测、但语义是错的。

    旧实现把「三百五」解析成 3*100+5 = **305**，我甚至在 docstring 里
    把这个错误当成"正确行为"写了进去 —— 于是写测试时也没怀疑它。
    实际上中文口语里「三百五」= **350**；305 必须说「三百零五」。
    也就是说 **「零」是显式的个位标记**：有零才是零头，没零就是下级单位。

    正确规则（与口语一致）：
      三百五   → 3*100 + 5*10  = 350   （末位残留数按下一级单位进位）
      三百五十 → 3*100 + 5*10  = 350
      三百零五 → 3*100 + 0 + 5 = 305   （零显式清零，末位不再进位）
      五百     → 500
      一千二   → 1200
      两千三   → 2300
    """
    if not s:
        return None
    total, section = 0, 0
    pending_scale = 0          # 最后一个百/十的单位，用于处理残留个位
    has_zero = False           # 出现过「零」→ 后续残留数是零头，不进位

    for ch in s:
        if ch == '零':
            total += section
            section = 0
            has_zero = True
            pending_scale = 0
        elif ch in NUMBER_CN and ch != '十':
            # 裸数字本身不清 pending_scale —— 否则「三百五」的进位会丢
            # （五 把 百 留下的 scale 清掉，结果又变回 305）。
            # 真正要清的是「十」那一支：因为「十五」里 十 已经把 section 乘过
            # 10 并累加进 total 了，若再让末尾的 5 乘一次 scale 就成了 60。
            section = NUMBER_CN[ch]
        elif ch == '十':
            section = (section or 1) * 10
            total += section
            section = 0
            # 十 已经消化过这次乘法，残留位不再进位。
            pending_scale = 0
        elif ch == '百':
            total += (section or 1) * 100
            section = 0
            pending_scale = 10
            has_zero = False
        elif ch == '千':
            total += (section or 1) * 1000
            section = 0
            pending_scale = 100
            has_zero = False
        else:
            return None

    # 末位残留数：没有「零」时按口语进位到下一级单位
    if section and pending_scale and not has_zero:
        total += section * pending_scale
        section = 0
    return total + section


# ── 中文数字：只在明确的"钱"上下文里才算金额 ──────────────────────
#
# 这里记录一次完整的踩坑过程，因为它说明了一个通用的教训：
#
#   第一版：完全不限单位 → 「调一下额度」「第一次转账」里的"一"被当成 1 元。
#   第二版：强制要求后面跟单位 → 「给李娜转五百」也丢了，过度收紧。
#   第三版：允许裸中文数字 + 靠 scrub 过滤 → 「一下」又被捡回来，回到原点。
#
# 根因是**「三百五」和「第一次」在字面上没有区别**——
# 同样的中文数字序列，一个指金额一个不指。靠模式匹配无法可靠区分。
# 所以最终方案是要求显式的钱标记（元/块/圆），歧义就自然消失了。
# 代价是「转五百」这种省略说法必须追问一次；
# 但金额猜错的代价（转 5 元 vs 转 500 元）远高于多问一句。
_CN_AMOUNT_RE = re.compile(
    r'([零一两二三四五六七八九十百千]{1,10})\s*(元|块|圆)'
)
# 含「千」的中文数字串（最大连续匹配）。
#
# 这里的 (?=...) 是个**前瞻，不消耗字符**，作用是先把"后面确实是中文数字"
# 的部分一起圈进来，再交给 _cn_small 处理口语进位。
# 之所以用前瞻而不是把尾数写进字符类：写进字符类会让「一千二」的匹配
# 在「一千」处提前结束（{1,8} 配到"一"，然后"千"满足固定部分即算完成），
# 于是 _cn_small 只收到"一千"，算出 1000 而不是 1200。
#
# 注意这里**不处理「万」**：「一万二」口语上可能是 12000 也可能是 10002，
# 无法从字面判断。按"宁可不认、不猜"的原则返回 None 让用户澄清。
_CN_QIAN_RE = re.compile(r'[一两二三四五六七八九]千(?=[零一两二三四五六七八九十]|$)')
# 完整中文数字串（含千），用于无「元」字的口语说法
_CN_PLAIN_RE = re.compile(r'[零一两二三四五六七八九十百千万亿]{1,12}')


def _cn_amount(scrub):
    """从文本里找第一个可解析的中文数字串。返回元或 None。

    策略：取**最大连续中文数字串**，而不是用复杂正则去描述它的边界。
    字符集是已知的（零一二两三四五六七八九十百千万亿），所以直接取连续段
    比堆叠前瞻/后顾更可靠 —— 我在这上面连续错了三次，教训是
    "用正则描述一个可以用字符集直接切分的边界"是自找麻烦。
    """
    for m in _CN_PLAIN_RE.finditer(scrub):
        raw = m.group(0)
        if '万' in raw or '亿' in raw:
            continue          # 含万的缩写有歧义，不猜
        val = _cn_small(raw)
        if val:
            return float(val)
    return None
# 「两块五」这类口语小数：元/块 夹在中间，本身就是强信号
_CN_DECIMAL_RE = re.compile(
    r'([一两二三四五六七八九十])\s*(?:块|元|圆)\s*([零一两二三四五六七八九])\s*(?:毛|角)?'
)


def parse_amount_yuan(text):
    """从文本里抽金额（返回元）。

    支持：'500'、'500块'、'500元'、'1.5万'、'两千'、'五百'、'三百五'、'两块五'
    找不到返回 None（**不猜** —— 猜错金额比问一句代价大得多）。

    顺序很重要：先擦掉账号（A001）、日期（3月）这类"看着像数字"的干扰，
    再找金额；中文数字必须带单位才认。
    """
    if not text:
        return None

    # ── 先屏蔽干扰源 ────────────────────────────────────────────────
    # 注意不能用 \b：中文也是"word 字符"，所以「把A004」在 A 前面**没有**
    # 词边界，`\bA0*\d+\b` 永远匹配不上，scrub 会静默失效。
    # 实测教训：这个 bug 让「把A004的钱转给A001」里的 4 被当成 4 元金额。
    scrub = re.sub(r'A0*\d+', ' ', text, flags=re.I)                  # 账号 A004
    # 量词表里**不能有「元/块/圆」**。踩过的坑：原先写成了
    # `\d+\s*(月|日|号|次|个|人|天|年|周|元)`，结果「赎回 1000 元货币基金」
    # 里的「1000 元」被整段擦掉，金额变成 None —— 用户说了金额却被告知没给。
    # 「元」是钱单位，是要保留的信号，不是要过滤的噪声。
    scrub = re.sub(r'\d+\s*(月|日|号|次|个|人|天|年|周)', ' ', scrub)  # 日期/量词

    # ── 阿拉伯数字 + 单位 ───────────────────────────────────────────
    # 注意单位里**不含「万/千」**。原因：万/千 是中文数量级，
    # 一旦把它们当阿拉伯数字的单位，「一千二」就会被
    # "一" + "千" 匹配成 1*1000=1000，中文分支永远没机会算 1200。
    # 数字配万/千 的说法（"1.5万"、"2千"）由下面单独的规则处理，那里能拿到完整数字。
    m = re.search(r'(\d+(?:\.\d+)?)\s*(块|元|圆|k|K|rmb|RMB)', scrub)
    if m:
        v = float(m.group(1))
        if m.group(2) in ('k', 'K'):
            v *= UNIT_QIAN
        return v

    # ── 阿拉伯数字 + 中文数量级：「1.5万」= 15000、「2千」= 2000 ─────
    m = re.search(r'(\d+(?:\.\d+)?)\s*(万|千)', scrub)
    if m:
        v = float(m.group(1))
        return v * (UNIT_WAN if m.group(2) == '万' else UNIT_QIAN)

    # ── 裸数字：前后都不能紧邻中文数字 ──────────────────────────────
    # 两端都要拦，只拦一端不够 —— 这是实测踩到的：
    # 只加 lookbehind 时，「一千二」里的 "2"（前面是"千"）被拒后，
    # 正则**从 "一" 重新起匹配**，于是拿到 1，再乘上后面的"千" = 1000。
    # 加了 lookahead 之后，这种单字紧邻中文数字的情况整体被跳过，
    # 后面才轮到中文分支把它正确算成 1200。
    m = re.search(r'(?<![零一二两三四五六七八九十百千万亿])'
                  r'(\d+(?:\.\d+)?)'
                  r'(?![零一二两三四五六七八九十百千万亿])', scrub)
    if m:
        return float(m.group(1))

    # ── 中文数字带小数：「两块五」= 2.5（元/块 是强信号，优先）──────
    m = _CN_DECIMAL_RE.search(scrub)
    if m:
        whole = NUMBER_CN.get(m.group(1))
        frac = NUMBER_CN.get(m.group(2))
        if whole is not None and frac is not None:
            return float(whole) + frac / 10.0

    # ── 中文数字 + 钱单位：「五百元」= 500、「三百五元」= 350 ─────────
    m = _CN_AMOUNT_RE.search(scrub)
    if m:
        base = _cn_small(m.group(1))
        if base is not None:
            return float(base)

    # ── 无「元」字的中文数字：「一千二」= 1200、「转五百」= None ─────
    # 注意「转五百」也会走到这里，而 _CN_PLAIN_RE 会匹配到"五百"
    # 并算出 500 —— 但前面已决定"无钱单位的中文数字不认"，
    # 这里靠"整串必须含 千"来区分：五百 不含千 → 跳过，返回 None。
    if _CN_QIAN_RE.search(scrub):
        return _cn_amount(scrub)

    return None


class Intent:
    def __init__(self, name, slots=None, confidence=0.0, raw=''):
        self.name = name
        self.slots = slots or {}
        self.confidence = confidence
        self.raw = raw

    def to_dict(self):
        return {'intent': self.name, 'slots': self.slots,
                'confidence': self.confidence, 'raw': self.raw}


class IntentParser:
    """把自然语言映射成 (意图, 槽位)。

    设计原则：**宁可说"我没听懂"，也不猜。**
    金额、收款人这类槽位猜错会造成真实损失，所以缺槽位时返回 needs 列表，
    由上层追问用户，而不是填一个默认值往下走。
    """

    def __init__(self, core):
        self.core = core

    def parse(self, text, session_state=None):
        t = (text or '').strip()
        if not t:
            return Intent('unknown', confidence=0.0, raw=t)

        # 顺序重要：先匹配更具体的意图，避免被泛化规则误捕
        # 顺序决定歧义归属，这里的次序是实测调出来的：
        #   卡 必须在 理财 **之前** —— 否则「买卡」会被理财的「买」拦走。
        #   理财 必须在 转账 **之前** —— 否则「赎回 1000 元」会被转账的金额规则吃掉。
        # 每条注释都对应一次真实的误判，改动前请先跑意图回归。
        for handler in (self._p_balance, self._p_bill, self._p_subscription,
                        self._p_card, self._p_wealth, self._p_linkage,
                        self._p_transfer, self._p_greeting):
            it = handler(t, session_state)
            if it:
                it.raw = t
                return it
        return Intent('unknown', confidence=0.0, raw=t)

    # ── 查询类 ────────────────────────────────────────────────────────
    def _p_balance(self, t, _):
        if re.search(r'余额|还有多少|账上|卡里|有多少钱', t):
            acct = self._extract_account(t) or 'A001'
            return Intent('query_balance', {'acct': acct}, 0.95)
        return None

    def _p_bill(self, t, _):
        if re.search(r'账单|消费|花了多少|支出|开销|流水', t):
            period = 'month'
            if re.search(r'年|年度|一年', t):
                period = 'year'
            elif re.search(r'周|这周|本周', t):
                period = 'week'
            acct = self._extract_account(t) or 'A001'
            return Intent('bill_analyze', {'acct': acct, 'period': period}, 0.9)
        if re.search(r'异常|可疑|盗刷|不对劲', t):
            acct = self._extract_account(t) or 'A001'
            return Intent('bill_anomaly', {'acct': acct}, 0.88)
        return None

    def _p_subscription(self, t, _):
        if re.search(r'订阅|自动续费|代扣|会员', t):
            acct = self._extract_account(t) or 'A001'
            if re.search(r'取消|关掉|退订|停了', t):
                merchant = self._extract_merchant(t, acct)
                if not merchant:
                    return Intent('subscription_cancel_need_merchant',
                                  {'acct': acct}, 0.7)
                return Intent('subscription_cancel',
                              {'acct': acct, 'merchant': merchant}, 0.9)
            return Intent('subscription_list', {'acct': acct}, 0.92)
        return None

    def _p_wealth(self, t, _):
        # 触发词必须包含「买/购买」——否则「买 5000 元稳健增利」
        # 这类不带「理财/基金」字样的说法完全进不来。
        # 「买卡」不会走到这里：卡场景在解析顺序上更靠前，已先一步截获。
        if re.search(r'理财|基金|收益|投资|申购|赎回|年化|买|购买', t):
            acct = self._extract_account(t) or 'A001'
            product = self._extract_product(t, acct)
            if re.search(r'赎回|取出|卖掉', t):
                # 金额必须一起带上 —— 漏了它会导致「赎回 1000 元X」被当成缺金额，
                # 走追问分支问用户"请问转多少钱？"（而且措辞还是转账的）。
                amt = parse_amount_yuan(t)
                return Intent('wealth_redeem',
                              {'acct': acct, 'product': product,
                               'amount_yuan': amt}, 0.85)
            # 「买」是口语最常见的申购说法，必须支持。
            # 但必须排除两类情况，否则会把「询问」误判成「申购」：
            #
            #   ① 「买卡」—— 属于卡场景（卡分支在前，本不该到此处，双保险）；
            #   ② 「可以买」「能买」「买什么」「买哪个」
            #      —— 这里的「买」是**询问语气**，不是申购。
            #
            # 第 ② 类是实测踩到的：「有哪些理财产品可以买」被判成
            # wealth_purchase，然后因缺金额被追问"请问申购多少元" ——
            # 而这恰恰是最自然的产品查询说法。判断依据是"列举/疑问"词形，
            # 不是"买"字本身。
            is_asking = re.search(r'可以买|能买|买什么|买哪|有哪些|有什么|看看', t)
            if re.search(r'申购|入手|购买|(?<!买)买(?!卡)', t) and not is_asking:
                amt = parse_amount_yuan(t)
                return Intent('wealth_purchase',
                              {'acct': acct, 'amount_yuan': amt,
                               'product': product}, 0.85)
            if re.search(r'我的|持仓|赚了|亏了|收益', t):
                return Intent('wealth_holdings', {'acct': acct}, 0.9)
            return Intent('wealth_list', {'acct': acct}, 0.9)
        return None

    def _p_linkage(self, t, _):
        """跨场景联动（赛题场景 6）。

        典型说法：「我爱人生日，帮我当月锁定 1000 元，生日前 2 天订鲜花蛋糕」

        要点是**跨领域**：时间（生日前 2 天）+ 资金预留（锁定 1000）+ 外部订购
        （鲜花、蛋糕）+ 提醒。所以这里要抽的不只是金额，还有「事件」与「人」。

        时间词处理：**不在这里解析相对日期**（"生日前 2 天"要基于生日才能算）。
        解析器只负责认出这是一条联动需求并抽出事件/人/预算，
        具体日期由编排层按事件日期推算 —— 这样职责清楚，
        也避免解析器里出现第二套日期逻辑。
        """
        KEY = r'生日|纪念日|节日|送礼|礼物|鲜花|蛋糕|联动|提前准备|备忘'
        if not re.search(KEY, t) and not re.search(r'锁定.*(?:元|块).*?(?:准备|到时候|生日)', t):
            return None

        acct = self._extract_account(t) or 'A001'
        wants_order = bool(re.search(r'订|下单|买|鲜花|蛋糕|礼物', t))
        wants_lock = bool(re.search(r'锁定|预留|冻结(?:一笔|资金)|圈起来|别动', t))

        # ── 查计划 ────────────────────────────────────────────────────
        if re.search(r'有(?:哪些|什么|没有).*(?:计划|安排)|我的.*(?:联动|计划|安排)', t):
            return Intent('linkage_list', {'acct': acct}, 0.9)

        # ── 纯锁定（没有订购意图）→ 单独动作 ──────────────────────────
        # 判定依据是"有没有订购意图"，不是"有没有订购词"：
        # 「生日前2天订鲜花蛋糕」也含"订"，但它表达的是**登记一个计划**，
        # 而不是"现在就下单"。若按词判定，赛题的原句会被错判成立即执行。
        if wants_lock and not wants_order:
            amt = parse_amount_yuan(t)
            return Intent('linkage_lock',
                          {'acct': acct, 'amount_yuan': amt,
                           'occasion_text': self._extract_occasion(t)}, 0.88)

        # ── 显式要求执行 ──────────────────────────────────────────────
        if re.search(r'执行|现在(?:就)?(?:订|买|办)|立即(?:订|买)|到期|跑一下', t):
            return Intent('linkage_run',
                          {'acct': acct, 'occasion_text': self._extract_occasion(t)}, 0.85)

        # ── 登记计划（默认分支）──────────────────────────────────────
        # auto_lock：用户在同句里说了"锁定"，说明他要一步到位。
        # 但锁定本身仍有独立分级（黄色需确认），这里只是把两步串起来。
        amt = parse_amount_yuan(t)
        return Intent('linkage_create',
                      {'acct': acct,
                       'amount_yuan': amt,
                       'occasion_text': self._extract_occasion(t),
                       'person': self._extract_person(t),
                       'event_date': self._extract_date(t),
                       'auto_lock': wants_lock}, 0.87)

    def _extract_occasion(self, t):
        """抽出事件类型。目前支持的几类都映射到一个标准事件名。"""
        table = [
            ('爱人生日', r'爱人.*生日|老婆.*生日|先生.*生日|伴侣.*生日'),
            ('父母生日', r'(?:爸|妈|父亲|母亲|父母).*生日'),
            ('子女生日', r'(?:孩子|儿子|女儿|宝宝).*生日'),
            ('生日', r'生日'),
            ('纪念日', r'纪念日|结婚纪念'),
            ('节日', r'节日|过节|春节|中秋|端午'),
        ]
        for name, pat in table:
            if re.search(pat, t):
                return name
        return None

    def _extract_person(self, t):
        m = re.search(r'(爱人|老婆|老公|先生|太太|伴侣|爸爸|妈妈|父亲|母亲|'
                      r'儿子|女儿|孩子|宝宝)', t)
        return m.group(1) if m else None

    def _extract_date(self, t):
        """抽出显式日期（YYYY-MM-DD / M月D日）。

        只说"生日"而不给日期的，**这里返回 None**，由编排层用配置里的
        默认事件日期兜底或向用户追问 —— 猜一个生日比问一句危险得多。
        """
        m = re.search(r'(\d{4})-(\d{1,2})-(\d{1,2})', t)
        if m:
            return '%04d-%02d-%02d' % (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        m = re.search(r'(\d{1,2})\s*月\s*(\d{1,2})\s*[日号]', t)
        if m:
            return '2026-%02d-%02d' % (int(m.group(1)), int(m.group(2)))
        return None

    def _extract_product(self, t, acct):
        """识别用户说的是哪个理财产品。

        三种情况：
          1. 原样说出产品名（「稳健增利 90 天」）→ 直接命中；
          2. 模糊说法（「那个货币基金」「90 天那个」）→ 用关键词包含匹配；
          3. **没说产品名但持仓只有一个**（「赎回我的理财」）→ 补全为那一个。
        第 3 种是有意的：只有一个持仓时追问"你要赎回哪个"既啰嗦又没意义。
        但持仓有多个时**不猜** —— 返回 None 让上层追问，因为赎回错产品是资金误解。
        """
        # 1) 产品名原样出现
        for spec in WEALTH_CATALOG:
            if spec['name'] in t:
                return spec['name']
        # 2) 关键词包含匹配：取产品名里的特征词
        keys = {'货币基金 A': ['货币', '货币基金'],
                '稳健增利 90 天': ['稳健', '增利', '90天', '90 天'],
                '固收增强 180 天': ['固收', '增强', '180天', '180 天'],
                '指数增强组合': ['指数', '组合']}
        for name, kws in keys.items():
            if any(k in t for k in kws):
                return name
        # 3) 未指名：只在持仓唯一时补全
        held = [h['product'] for h in self.core.holdings(acct)]
        if len(held) == 1:
            return held[0]
        return None

    def _p_card(self, t, _):
        if re.search(r'挂失|冻结|锁卡|丢卡|卡片丢失', t):
            acct = self._extract_account(t) or 'A001'
            return Intent('card_freeze', {'acct': acct}, 0.93)
        if re.search(r'解挂|解冻|恢复用卡', t):
            acct = self._extract_account(t) or 'A001'
            return Intent('card_unfreeze', {'acct': acct}, 0.9)
        if re.search(r'额度|限额|提额', t):
            acct = self._extract_account(t) or 'A001'
            amt = parse_amount_yuan(t)
            return Intent('card_limit_change',
                          {'acct': acct, 'limit_yuan': amt}, 0.82)
        # 注意这里**不能出现裸「买」**。原先写的是 `虚拟卡|新卡|开卡|办卡|买卡|申请卡`，
        # 其中「买卡」里的「买」会抢先匹配「买 5000 元理财」—— 因为卡场景在
        # 意图解析顺序里排在理财之前。修法是要求「买」必须与卡同时出现。
        # 允许空格：「买 卡」「买一张 卡」都算。
        if re.search(r'虚拟卡|新卡|开卡|办卡|申请卡|办一张卡|买\s*一?\s*张?\s*卡', t):
            acct = self._extract_account(t) or 'A001'
            return Intent('card_apply_virtual', {'acct': acct}, 0.9)
        return None

    def _p_transfer(self, t, _):
        # AA 收款是转账的变体，先判断
        if re.search(r'AA|aa|平摊|均摊|一起付', t):
            total = parse_amount_yuan(t)
            people = self._extract_people_count(t)
            return Intent('split_request',
                          {'acct': 'A001', 'total_yuan': total, 'people': people}, 0.85)

        if not re.search(r'转|汇|打钱|给.*钱|付款', t):
            return None

        amount_yuan = parse_amount_yuan(t)
        payee_text = self._extract_payee_text(t)
        scheduled = bool(re.search(r'定时|明天|后天|下周|每月|每天|预约', t))

        slots = {'acct': 'A001'}
        missing = []
        if amount_yuan is None:
            missing.append('amount')
        else:
            slots['amount_yuan'] = amount_yuan
        if not payee_text:
            missing.append('payee')
        else:
            slots['payee_text'] = payee_text
        if scheduled:
            slots['scheduled'] = True

        # 收款人解析：按手机号 > 按姓名。重名时不擅自选，交回用户。
        if payee_text:
            candidates = self._resolve_payee(payee_text)
            if len(candidates) == 1:
                slots['to'] = candidates[0]['id']
                slots['to_name'] = candidates[0]['owner_name']
            elif len(candidates) > 1:
                slots['ambiguous'] = [{'id': c['id'], 'name': c['owner_name'],
                                       'phone': c['phone']} for c in candidates]
                missing.append('disambiguate')
            else:
                missing.append('payee_not_found')

        return Intent('transfer', slots, 0.9 if not missing else 0.6)

    def _p_greeting(self, t, _):
        if re.search(r'^(你好|您好|hi|hello|在吗|嗨)', t, re.I):
            return Intent('greeting', {}, 0.99)
        if re.search(r'能做什么|帮助|怎么用|功能', t):
            return Intent('help', {}, 0.95)
        return None

    # ── 槽位抽取辅助 ──────────────────────────────────────────────────
    def _extract_account(self, t):
        m = re.search(r'\b(A00\d)\b', t)
        return m.group(1) if m else None

    def _extract_payee_text(self, t):
        # 手机号优先
        m = re.search(r'\b(1[3-9]\d{9})\b', t)
        if m:
            return m.group(1)
        # 「给X转…」「转给X」「X 转」
        for pat in (r'给\s*([\u4e00-\u9fa5]{2,4})\s*(?:转|汇|打)',
                    r'转(?:给|账给)\s*([\u4e00-\u9fa5]{2,4})',
                    r'(?:向|和)\s*([\u4e00-\u9fa5]{2,4})\s*(?:转|付)'):
            m = re.search(pat, t)
            if m:
                name = m.group(1)
                # 过滤掉"我""他"这类代词和量词误捕
                if name not in ('我一', '我的', '自己'):
                    return name
        return None

    def _resolve_payee(self, text):
        if re.fullmatch(r'1[3-9]\d{9}', text):
            return self.core.find_by_phone(text)
        return self.core.find_by_name(text)

    def _extract_people_count(self, t):
        m = re.search(r'(\d+)\s*(?:个人|人|位)', t)
        if m:
            return int(m.group(1))
        m = re.search(r'([一两二三四五六七八九十]+)\s*(?:个人|人|位)', t)
        if m:
            return _cn_small(m.group(1))
        return None

    def _extract_merchant(self, t, acct):
        subs = self.core.conn.execute(
            'SELECT merchant FROM subscription WHERE acct=? AND status="active"',
            (acct,)).fetchall()
        for s in subs:
            if s['merchant'] in t:
                return s['merchant']
        # 「取消那个视频会员」这类模糊表达：关键词包含匹配
        for s in subs:
            key = re.sub(r'^某|会员$', '', s['merchant'])
            if key and key in t:
                return s['merchant']
        return None
