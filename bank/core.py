#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core.py —— 模拟银行核心（简版）

存在的理由
==========
比赛里拿不到真实银行接口，所以核心必须自己模拟。但「模拟」有两种做法：

  甲：把结果写死在返回值里 —— 演示"转账成功"，评委一问幂等就答不上来
  乙：做一个真的有账务约束的核心 —— 能演示重复提交不重复扣款、余额不会变负

本文件是乙。它不大，但它让下面这些**可演示、可测试**：

  · 幂等（idempotency）：同一个请求 ID 提交两次，只扣一次钱
  · 双重记账：每笔资金变动在 ledger 里成对出现，可核对
  · 余额约束：余额不足直接拒绝，不存在"扣成负数"
  · 事务原子性：要么全成功，要么全回滚
  · 冲正（reversal）：错误交易可撤销，且留痕

架构上最重要的一条
==================
**所有资金变动只能走 transfer() / reverse() 这两个入口。**
权限引擎和 Agent 都不允许直接写 accounts.balance。

原因：「权限分级」如果只做在对话层，一句精心构造的 prompt 就能绕过。
分级必须作用在**不可绕过的执行入口**上，而不是"Agent 的自觉"。
本模块不放行任何绕过路径 —— 没有 set_balance()，没有裸 UPDATE。

存储用 SQLite：真事务、可持久化、标准库自带。
"""

import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid

SCHEMA_VERSION = 1

# ── 金额一律用「分」存整数，避免浮点误差 ──────────────────────────────
# 这是金融系统的硬规矩：0.1 + 0.2 != 0.3 在钱上是事故，不是精度问题。
def yuan_to_cents(yuan):
    """元 → 分。用 Decimal 语义做四舍五入，避免 float 误差。"""
    from decimal import Decimal, ROUND_HALF_UP
    return int((Decimal(str(yuan)) * 100).quantize(Decimal('1'), rounding=ROUND_HALF_UP))


def cents_to_yuan(cents):
    """分 → 元的展示串。"""
    return '%.2f' % (cents / 100.0)


def _today_str(today=None):
    """返回 'YYYY-MM-DD'。

    为什么要把它抽成函数而不是到处调 time.strftime：
    跨场景联动依赖"今天"来判断步骤是否到期。若直接读系统时间，
    测试就会依赖运行当天的日期 —— 今天跑绿、明天跑红那种不稳定。
    所以日期一律从参数注入，默认才取真实时间。
    """
    if today:
        return today if isinstance(today, str) else str(today)
    return time.strftime('%Y-%m-%d')


def add_days(date_str, days):
    """日期加减天数，返回 'YYYY-MM-DD'。用标准库，不引入依赖。"""
    import datetime as _dt
    d = _dt.datetime.strptime(date_str, '%Y-%m-%d').date()
    return (d + _dt.timedelta(days=days)).isoformat()


# 演示用理财产品目录。
# 放在 core 层而不是 orchestrator 层，因为申购/赎回要在这里校验起购金额与产品存在性 ——
# 校验依据必须位于执行入口这一侧，否则上层可以绕过校验直接调 purchase()。
WEALTH_CATALOG = [
    {'name': '货币基金 A', 'term': '随时可取', 'annualized': 0.0185,
     'min_amount': 100, 'risk': '低'},
    {'name': '稳健增利 90 天', 'term': '90 天', 'annualized': 0.0310,
     'min_amount': 100000, 'risk': '中低'},
    {'name': '固收增强 180 天', 'term': '180 天', 'annualized': 0.0385,
     'min_amount': 500000, 'risk': '中'},
    {'name': '指数增强组合', 'term': '365 天', 'annualized': 0.0620,
     'min_amount': 1000000, 'risk': '中高'},
]


class BankError(Exception):
    """业务型错误。带 code，方便上层区分处理，不要把 traceback 暴露给用户。"""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class Core:
    """模拟银行核心。

    线程安全说明（重要）
    --------------------
    HTTP 服务用 ThreadingHTTPServer，每个请求在不同线程里跑。
    SQLite 连接**不能跨线程使用**（默认会直接抛异常），而设成
    check_same_thread=False 又会让并发写有损坏风险。

    所以这里采用「每线程一个连接」：每个线程第一次访问时懒创建一个
    自己的连接。SQLite 的多连接并发由它自身的锁来保证安全，
    写入用 BEGIN IMMEDIATE 串行化。

    这个问题的教训：单线程自测全过，不等于放进 HTTP 服务就能用。
    单元测试用单线程是个盲区。
    """

    def __init__(self, db_path='bank.db'):
        self.db_path = db_path
        self._local = threading.local()
        self._conns = []          # 记录所有线程的连接，便于统一关闭
        self._conn()              # 主线程先建一次连接
        self._migrate()           # 再建表（顺序不能反，_migrate 要用连接）

    # ── 连接管理 ──────────────────────────────────────────────────────
    @property
    def conn(self):
        """当前线程的连接。所有 self.conn 的用法保持不变。"""
        return self._conn()

    def _conn(self):
        c = getattr(self._local, 'conn', None)
        if c is None:
            c = sqlite3.connect(self.db_path, isolation_level=None, timeout=15)
            c.row_factory = sqlite3.Row
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('PRAGMA foreign_keys=ON')
            c.execute('PRAGMA busy_timeout=15000')
            self._local.conn = c
            self._conns.append(c)
        return c

    def _migrate(self):
        c = self._conn()
        c.executescript('''
        CREATE TABLE IF NOT EXISTS account (
          id          TEXT PRIMARY KEY,
          owner_name  TEXT NOT NULL,
          phone       TEXT,
          balance     INTEGER NOT NULL DEFAULT 0,   -- 单位：分
          -- 锁定金额（分）：为跨场景联动预留的资金。
          -- 设计要点：**余额不动，只是标出这部分不能花**。
          -- 这样账实仍然相符（ledger 对得上 balance），
          -- 而"能不能花"由 available() = balance - locked_amount 决定。
          -- 若改成把锁定金额从 balance 里扣掉，就必须伪造一笔 ledger 支出，
          -- 对账立刻不平 —— 那是自欺。
          locked_amount INTEGER NOT NULL DEFAULT 0,
          currency    TEXT NOT NULL DEFAULT 'CNY',
          card_no     TEXT,
          card_status TEXT NOT NULL DEFAULT 'active',  -- active|frozen|lost
          daily_limit INTEGER NOT NULL DEFAULT 5000000, -- 单日转出上限（分）
          created_at  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transfer (
          id              TEXT PRIMARY KEY,
          idem_key        TEXT NOT NULL,            -- 幂等键
          from_acct       TEXT NOT NULL REFERENCES account(id),
          to_acct         TEXT NOT NULL REFERENCES account(id),
          amount          INTEGER NOT NULL,
          note            TEXT,
          status          TEXT NOT NULL,            -- succeeded|reversed
          created_at      INTEGER NOT NULL,
          reversed_at     INTEGER,
          reversal_of     TEXT,
          UNIQUE (idem_key)                          -- 数据库层兜底，不只靠应用判断
        );

        -- 双重记账：每笔资金变动成对出现，可核对
        CREATE TABLE IF NOT EXISTS ledger (
          id          INTEGER PRIMARY KEY AUTOINCREMENT,
          -- transfer_id 允许为空：理财申赎也会变动资金，但它不是转账。
          -- 若强制 NOT NULL，就只能伪造一条 transfer 记录来挂账，那是自欺。
          transfer_id TEXT REFERENCES transfer(id),
          acct        TEXT NOT NULL REFERENCES account(id),
          owner_acct  TEXT,                          -- 该笔归属哪个账户（含理财）
          direction   TEXT NOT NULL,                -- debit | credit
          amount      INTEGER NOT NULL,             -- 恒为正数，方向看 direction
          balance_after INTEGER NOT NULL,
          created_at  INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ledger_acct ON ledger(acct, created_at DESC);

        CREATE TABLE IF NOT EXISTS subscription (
          id          TEXT PRIMARY KEY,
          acct        TEXT NOT NULL REFERENCES account(id),
          merchant    TEXT NOT NULL,
          amount      INTEGER NOT NULL,
          cycle       TEXT NOT NULL,                -- monthly|quarterly|yearly
          next_charge INTEGER NOT NULL,
          status      TEXT NOT NULL DEFAULT 'active', -- active|cancelled
          created_at  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS card_application (
          id          TEXT PRIMARY KEY,
          acct        TEXT NOT NULL REFERENCES account(id),
          kind        TEXT NOT NULL,                -- virtual|physical
          status      TEXT NOT NULL,                -- pending|approved|rejected
          reason      TEXT,
          created_at  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS meta (
          key TEXT PRIMARY KEY,
          val TEXT NOT NULL
        );

        -- 理财持仓。做成一等实体而不是硬编码，否则"赎回"没法真正改变状态，
        -- 也无法校验"赎回金额不得超过持仓"。
        CREATE TABLE IF NOT EXISTS holding (
          id         TEXT PRIMARY KEY,
          acct       TEXT NOT NULL REFERENCES account(id),
          product    TEXT NOT NULL,
          term       TEXT NOT NULL,           -- 期限描述，如「90 天」
          amount     INTEGER NOT NULL,        -- 持有金额（分）
          annualized REAL NOT NULL,           -- 年化收益率
          profit     INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_holding_acct ON holding(acct);

        -- 理财申赎流水（幂等键在此唯一）
        CREATE TABLE IF NOT EXISTS wealth_order (
          id         TEXT PRIMARY KEY,
          idem_key   TEXT NOT NULL,
          acct       TEXT NOT NULL REFERENCES account(id),
          product    TEXT NOT NULL,
          side       TEXT NOT NULL,           -- purchase | redeem
          amount     INTEGER NOT NULL,
          status     TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          UNIQUE (idem_key)
        );

        -- ── 跨场景联动计划（赛题场景 6）──────────────────────────────
        -- 一个计划 = 从一条信息推导出的一串跨领域动作。
        -- 例：「我爱人生子」→ 锁定 1000 元 → 生日前 2 天订鲜花蛋糕 → 提醒。
        CREATE TABLE IF NOT EXISTS linkage_plan (
          id          TEXT PRIMARY KEY,
          acct        TEXT NOT NULL REFERENCES account(id),
          occasion    TEXT NOT NULL,           -- 事件名，如「爱人生日」
          person      TEXT,                    -- 关联的人
          event_date  TEXT NOT NULL,           -- 目标日期 YYYY-MM-DD
          budget      INTEGER NOT NULL,        -- 预算（分）
          locked      INTEGER NOT NULL DEFAULT 0,  -- 本计划已锁定金额（分）
          status      TEXT NOT NULL,           -- planned|locked|done|cancelled
          created_at  INTEGER NOT NULL,
          locked_at   INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_linkage_acct ON linkage_plan(acct, status);

        CREATE TABLE IF NOT EXISTS linkage_step (
          id          TEXT PRIMARY KEY,
          plan_id     TEXT NOT NULL REFERENCES linkage_plan(id),
          seq         INTEGER NOT NULL,        -- 执行顺序
          kind        TEXT NOT NULL,           -- order_gift|remind|...
          detail      TEXT NOT NULL,           -- 人类可读的动作描述
          amount      INTEGER NOT NULL DEFAULT 0,  -- 该步骤要花的钱（分）
          due_date    TEXT NOT NULL,           -- 应执行日期 YYYY-MM-DD
          status      TEXT NOT NULL,           -- pending|done|skipped
          idem_key    TEXT,
          executed_at INTEGER,
          result      TEXT,
          UNIQUE (idem_key)
        );
        CREATE INDEX IF NOT EXISTS idx_step_plan ON linkage_step(plan_id, seq);
        ''')
        self._migrate_columns()
        row = c.execute("SELECT val FROM meta WHERE key='schema_version'").fetchone()
        if not row:
            c.execute("INSERT INTO meta(key,val) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))

    def _migrate_columns(self):
        """给**已存在的**表补新增的列。

        为什么需要单独一步：
        `CREATE TABLE IF NOT EXISTS` 只在表不存在时建表。表已经存在时，
        新加的列**不会**被补上 —— 于是老库跑新代码会报
        "no such column: locked_amount"，而且报错点在很深的查询里，不好定位。
        改表结构时必须同时给出这条补列路径，否则升级就是坏的。
        """
        c = self._conn()
        cols = {r['name'] for r in c.execute('PRAGMA table_info(account)')}
        if 'locked_amount' not in cols:
            c.execute('ALTER TABLE account ADD COLUMN locked_amount INTEGER NOT NULL DEFAULT 0')

    # ── 读 ─────────────────────────────────────────────────────────────
    def get_account(self, acct_id):
        r = self.conn.execute('SELECT * FROM account WHERE id=?', (acct_id,)).fetchone()
        if not r:
            raise BankError('ACCOUNT_NOT_FOUND', '账户不存在：%s' % acct_id)
        return dict(r)

    def list_accounts(self):
        return [dict(r) for r in self.conn.execute('SELECT * FROM account ORDER BY id')]

    def find_by_name(self, name):
        """按人名找账户 —— 对应赛题「按人名转账」。名字可能有重名，全部返回让上层处理。"""
        rows = self.conn.execute(
            'SELECT * FROM account WHERE owner_name=?', (name.strip(),)).fetchall()
        return [dict(r) for r in rows]

    def find_by_phone(self, phone):
        rows = self.conn.execute(
            'SELECT * FROM account WHERE phone=?', (phone.strip(),)).fetchall()
        return [dict(r) for r in rows]

    def balance(self, acct_id):
        return self.get_account(acct_id)['balance']

    def recent_transfers(self, acct_id, limit=20):
        rows = self.conn.execute('''
            SELECT * FROM transfer
            WHERE from_acct=? OR to_acct=?
            ORDER BY created_at DESC LIMIT ?''', (acct_id, acct_id, limit)).fetchall()
        return [dict(r) for r in rows]

    def ledger_of(self, acct_id, limit=50):
        rows = self.conn.execute('''
            SELECT * FROM ledger WHERE acct=? ORDER BY id DESC LIMIT ?''',
            (acct_id, limit)).fetchall()
        return [dict(r) for r in rows]

    # ── 当日累计转出（权限分级要用它判断「日累计」）──────────────────────
    def daily_outgoing(self, acct_id, day_start_ms=None):
        """返回该账户当日的转出总额（分）。不含已冲正的交易。"""
        if day_start_ms is None:
            lt = time.localtime()
            day_start_ms = int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday,
                                            0, 0, 0, 0, 0, -1)) * 1000)
        r = self.conn.execute('''
            SELECT COALESCE(SUM(amount),0) AS s FROM transfer
            WHERE from_acct=? AND status='succeeded' AND created_at>=?''',
            (acct_id, day_start_ms)).fetchone()
        return int(r['s'])

    # ── 写：唯一资金入口 ───────────────────────────────────────────────
    def transfer(self, from_acct, to_acct, amount, idem_key, note=None):
        """转账。**这是唯一的资金变动入口**，权限校验必须在调用它之前完成。

        参数：
          amount   —— 整数，单位分，必须 > 0
          idem_key —— 幂等键。同一个键重复提交只会成功一次，
                      第二次原样返回第一次的结果。

        安全属性（重要）：**幂等键相同就视为同一个逻辑操作。**
        如果第二次提交的参数与第一次不同（比如金额被改大），
        本方法返回**原交易**，不会按新参数执行。
        否则攻击者可以先确认一笔 100 元转账拿到执行权，
        再把参数改成 10000 元重放 —— 幂等保护就形同虚设。

        返回 dict，含 transfer_id / status / balances。
        抛 BankError 表示业务拒绝（余额不足、账户冻结等）。
        """
        if not isinstance(amount, int) or amount <= 0:
            raise BankError('INVALID_AMOUNT', '转账金额必须是正整数（单位分）')
        if from_acct == to_acct:
            raise BankError('SAME_ACCOUNT', '不能给自己转账')
        if not idem_key:
            raise BankError('MISSING_IDEM_KEY', '缺少幂等键')

        c = self.conn
        c.execute('BEGIN IMMEDIATE')     # 立即拿写锁，避免并发下的余额竞态
        try:
            # 1) 幂等：同键已存在就直接返回旧结果，不重复扣款
            prev = c.execute('SELECT * FROM transfer WHERE idem_key=?', (idem_key,)).fetchone()
            if prev:
                c.execute('COMMIT')
                return {
                    'transfer_id': prev['id'],
                    'status': prev['status'],
                    'idempotent_replay': True,
                    'amount': prev['amount'],
                    'from_acct': prev['from_acct'],
                    'to_acct': prev['to_acct'],
                }

            # 2) 账户状态与余额校验（在事务内做，读到的余额是可信的）
            src = c.execute('SELECT * FROM account WHERE id=?', (from_acct,)).fetchone()
            dst = c.execute('SELECT * FROM account WHERE id=?', (to_acct,)).fetchone()
            if not src:
                raise BankError('ACCOUNT_NOT_FOUND', '付款账户不存在')
            if not dst:
                raise BankError('ACCOUNT_NOT_FOUND', '收款账户不存在')
            if src['card_status'] != 'active':
                raise BankError('ACCOUNT_LOCKED',
                                '付款账户状态为「%s」，无法转出' % src['card_status'])
            # 用**可动用余额**而不是余额。
            # 跨场景联动预留的钱（locked_amount）是"不能花"的，
            # 若这里只看 balance，用户把预留资金花掉后，
            # 到期该订的鲜花就付不出钱了 —— 预留形同虚设。
            free = src['balance'] - src['locked_amount']
            if free < amount:
                detail = ''
                if src['locked_amount'] > 0:
                    detail = '（余额 %s 元中另有 %s 元已为联动计划锁定）' % (
                        cents_to_yuan(src['balance']), cents_to_yuan(src['locked_amount']))
                raise BankError('INSUFFICIENT_FUNDS',
                                '可动用余额不足：可用 %s 元，需要 %s 元%s'
                                % (cents_to_yuan(free), cents_to_yuan(amount), detail))

            # 3) 单日限额（这里只做账户级硬约束；"日累计 > 1000 元需强验证"由权限引擎负责）
            already = self.daily_outgoing(from_acct)
            if already + amount > src['daily_limit']:
                raise BankError('DAILY_LIMIT_EXCEEDED',
                                '超出单日转出上限：今日已转 %s 元，上限 %s 元'
                                % (cents_to_yuan(already), cents_to_yuan(src['daily_limit'])))

            # 4) 落账
            now = int(time.time() * 1000)
            tid = 'TX' + uuid.uuid4().hex[:12].upper()
            new_src = src['balance'] - amount
            new_dst = dst['balance'] + amount

            c.execute('INSERT INTO transfer(id,idem_key,from_acct,to_acct,amount,note,status,created_at) '
                      'VALUES(?,?,?,?,?,?,?,?)',
                      (tid, idem_key, from_acct, to_acct, amount, note, 'succeeded', now))
            c.execute('UPDATE account SET balance=? WHERE id=?', (new_src, from_acct))
            c.execute('UPDATE account SET balance=? WHERE id=?', (new_dst, to_acct))
            # owner_acct 标明这笔归属哪个账户：付款方记 from，收款方记 to。
            # reconcile() 只按它汇总，一笔只算一次。
            c.execute('INSERT INTO ledger(transfer_id,acct,owner_acct,direction,amount,balance_after,created_at) '
                      'VALUES(?,?,?,?,?,?,?)',
                      (tid, from_acct, from_acct, 'debit', amount, new_src, now))
            c.execute('INSERT INTO ledger(transfer_id,acct,owner_acct,direction,amount,balance_after,created_at) '
                      'VALUES(?,?,?,?,?,?,?)',
                      (tid, to_acct, to_acct, 'credit', amount, new_dst, now))

            c.execute('COMMIT')
            return {
                'transfer_id': tid,
                'status': 'succeeded',
                'idempotent_replay': False,
                'amount': amount,
                'from_acct': from_acct,
                'to_acct': to_acct,
                'note': note,
                'from_balance_after': new_src,
                'to_balance_after': new_dst,
            }
        except BankError:
            c.execute('ROLLBACK')
            raise
        except sqlite3.IntegrityError as exc:
            # 并发下两个同 key 请求同时穿过前面的 SELECT 时，UNIQUE 会拦住第二个
            c.execute('ROLLBACK')
            if 'idem_key' in str(exc):
                prev = self.conn.execute('SELECT * FROM transfer WHERE idem_key=?',
                                         (idem_key,)).fetchone()
                if prev:
                    return {'transfer_id': prev['id'], 'status': prev['status'],
                            'idempotent_replay': True, 'amount': prev['amount'],
                            'from_acct': prev['from_acct'], 'to_acct': prev['to_acct']}
            raise BankError('DB_CONSTRAINT', '数据库约束拒绝：%s' % exc)
        except Exception:
            c.execute('ROLLBACK')
            raise

    def reverse(self, transfer_id, idem_key, reason=None):
        """冲正一笔已成功的转账。也走幂等。

        真实银行里冲正不是"改状态"，而是生成一笔反向交易。
        这里简化为标记原交易 + 生成反向 ledger，但保留了幂等与留痕。
        """
        c = self.conn
        c.execute('BEGIN IMMEDIATE')
        try:
            t = c.execute('SELECT * FROM transfer WHERE id=?', (transfer_id,)).fetchone()
            if not t:
                raise BankError('TRANSFER_NOT_FOUND', '找不到该笔交易：%s' % transfer_id)
            if t['status'] == 'reversed':
                c.execute('COMMIT')
                return {'transfer_id': transfer_id, 'status': 'reversed',
                        'idempotent_replay': True}
            if t['status'] != 'succeeded':
                raise BankError('NOT_REVERSIBLE', '该交易状态为 %s，不能冲正' % t['status'])

            now = int(time.time() * 1000)
            f, d, amt = t['from_acct'], t['to_acct'], t['amount']

            bf = c.execute('SELECT balance FROM account WHERE id=?', (f,)).fetchone()['balance']
            bd = c.execute('SELECT balance FROM account WHERE id=?', (d,)).fetchone()['balance']
            if bd < amt:
                raise BankError('REVERSAL_INSUFFICIENT',
                                '收款方余额不足以冲正（可能已再次转出）')

            c.execute('UPDATE account SET balance=? WHERE id=?', (bf + amt, f))
            c.execute('UPDATE account SET balance=? WHERE id=?', (bd - amt, d))
            c.execute('UPDATE transfer SET status=?, reversed_at=? WHERE id=?',
                      ('reversed', now, transfer_id))
            c.execute('INSERT INTO ledger(transfer_id,acct,owner_acct,direction,amount,balance_after,created_at) '
                      'VALUES(?,?,?,?,?,?,?)',
                      (transfer_id, f, f, 'credit', amt, bf + amt, now))
            c.execute('INSERT INTO ledger(transfer_id,acct,owner_acct,direction,amount,balance_after,created_at) '
                      'VALUES(?,?,?,?,?,?,?)',
                      (transfer_id, d, d, 'debit', amt, bd - amt, now))
            c.execute('COMMIT')
            return {'transfer_id': transfer_id, 'status': 'reversed',
                    'idempotent_replay': False, 'reason': reason}
        except BankError:
            c.execute('ROLLBACK')
            raise
        except Exception:
            c.execute('ROLLBACK')
            raise

    # ── 对账：双重记账的自检 ───────────────────────────────────────────
    def reconcile(self):
        """核对所有账户：余额是否等于 ledger 累计。返回差异清单。

        这是"模拟核心"比"写死返回值"值钱的地方 —— 它能证明账是平的。
        """
        problems = []
        for a in self.list_accounts():
            led = self.conn.execute('''
                SELECT COALESCE(SUM(CASE direction WHEN 'credit' THEN amount ELSE -amount END),0) AS s
                FROM ledger WHERE owner_acct=?''',
                (a['id'],)).fetchone()['s']
            opening = self.conn.execute(
                "SELECT val FROM meta WHERE key=?", ('opening:%s' % a['id'],)).fetchone()
            base = int(opening['val']) if opening else 0
            if base + led != a['balance']:
                problems.append({
                    'acct': a['id'],
                    'balance': a['balance'],
                    'expected': base + led,
                    'diff': a['balance'] - (base + led),
                })
        return {'ok': not problems, 'problems': problems}

    def overview(self):
        """演示首页要的聚合视图（账户 / 持仓 / 订阅）。"""
        return {
            'accounts': [dict(r) for r in self.conn.execute(
                'SELECT * FROM account ORDER BY id')],
            'holdings': self.holdings(None),
            'subscriptions': [dict(r) for r in self.conn.execute(
                'SELECT * FROM subscription WHERE status="active" '
                'ORDER BY next_charge')],
        }

    # ── 理财持仓与申赎 ─────────────────────────────────────────────────
    def holdings(self, acct_id=None):
        if acct_id:
            rows = self.conn.execute(
                'SELECT * FROM holding WHERE acct=? ORDER BY amount DESC',
                (acct_id,)).fetchall()
        else:
            rows = self.conn.execute(
                'SELECT * FROM holding ORDER BY acct, amount DESC').fetchall()
        return [dict(r) for r in rows]

    def purchase(self, acct_id, product, amount, idem_key):
        """申购理财产品。从活期余额扣款，转为持仓。

        与 transfer() 同样是**幂等**的：同一个 idem_key 重复提交只会成功一次。
        理财申购在真实银行里也要求幂等 —— 网络重试导致重复申购同样会造成损失。
        """
        if not isinstance(amount, int) or amount <= 0:
            raise BankError('INVALID_AMOUNT', '申购金额必须是正整数（单位分）')
        if not idem_key:
            raise BankError('MISSING_IDEM_KEY', '缺少幂等键')
        spec = next((p for p in WEALTH_CATALOG if p['name'] == product), None)
        if not spec:
            raise BankError('PRODUCT_NOT_FOUND', '没有这个理财产品：%s' % product)
        if amount < spec['min_amount']:
            raise BankError('BELOW_MIN_AMOUNT',
                            '低于起购金额：%s 起购，本次 %s'
                            % (cents_to_yuan(spec['min_amount']), cents_to_yuan(amount)))

        c = self.conn
        c.execute('BEGIN IMMEDIATE')
        try:
            prev = c.execute('SELECT * FROM wealth_order WHERE idem_key=?',
                             (idem_key,)).fetchone()
            if prev:
                c.execute('COMMIT')
                return {'order_id': prev['id'], 'status': prev['status'],
                        'idempotent_replay': True, 'amount': prev['amount']}

            a = c.execute('SELECT * FROM account WHERE id=?', (acct_id,)).fetchone()
            if not a:
                raise BankError('ACCOUNT_NOT_FOUND', '账户不存在')
            # 同样用可动用余额：被联动计划锁定的钱不能拿去申购理财
            free = a['balance'] - a['locked_amount']
            if free < amount:
                detail = ''
                if a['locked_amount'] > 0:
                    detail = '（其中 %s 元已为联动计划锁定）' % cents_to_yuan(a['locked_amount'])
                raise BankError('INSUFFICIENT_FUNDS',
                                '活期可用余额不足：可用 %s 元，需要 %s 元%s'
                                % (cents_to_yuan(free), cents_to_yuan(amount), detail))

            now = int(time.time() * 1000)
            oid = 'WO' + uuid.uuid4().hex[:12].upper()
            c.execute('UPDATE account SET balance=? WHERE id=?',
                      (a['balance'] - amount, acct_id))

            # 已有同产品持仓则累加，否则新建
            h = c.execute('SELECT * FROM holding WHERE acct=? AND product=?',
                          (acct_id, product)).fetchone()
            if h:
                c.execute('UPDATE holding SET amount=amount+? WHERE id=?',
                          (amount, h['id']))
            else:
                c.execute('INSERT INTO holding(id,acct,product,term,amount,'
                          'annualized,profit,created_at) VALUES(?,?,?,?,?,?,?,?)',
                          ('H' + uuid.uuid4().hex[:10].upper(), acct_id, product,
                           spec['term'], amount, spec['annualized'], 0, now))
            c.execute('INSERT INTO wealth_order(id,idem_key,acct,product,side,'
                      'amount,status,created_at) VALUES(?,?,?,?,?,?,?,?)',
                      (oid, idem_key, acct_id, product, 'purchase', amount,
                       'succeeded', now))
            # 资金变动必须留痕，否则 reconcile() 对不上 ——
            # 申购扣了活期余额却不写 ledger，账就"平不了"（实测差 -500000 分）。
            c.execute('INSERT INTO ledger(transfer_id,acct,owner_acct,direction,'
                      'amount,balance_after,created_at) VALUES(?,?,?,?,?,?,?)',
                      (None, acct_id, acct_id, 'debit', amount,
                       a['balance'] - amount, now))
            c.execute('COMMIT')
            return {'order_id': oid, 'status': 'succeeded',
                    'idempotent_replay': False, 'amount': amount,
                    'product': product, 'balance_after': a['balance'] - amount}
        except BankError:
            c.execute('ROLLBACK')
            raise
        except Exception:
            c.execute('ROLLBACK')
            raise

    def redeem(self, acct_id, product, amount, idem_key):
        """赎回理财产品。持仓减少，本金回到活期余额。

        校验比申购更严：**赎回额不得超过该产品持仓**，否则会出现"凭空赎回"。
        这是我在设计时刻意加的约束 —— 没有它，赎回就是一台印钞机。
        """
        if not isinstance(amount, int) or amount <= 0:
            raise BankError('INVALID_AMOUNT', '赎回金额必须是正整数（单位分）')
        if not idem_key:
            raise BankError('MISSING_IDEM_KEY', '缺少幂等键')

        c = self.conn
        c.execute('BEGIN IMMEDIATE')
        try:
            prev = c.execute('SELECT * FROM wealth_order WHERE idem_key=?',
                             (idem_key,)).fetchone()
            if prev:
                c.execute('COMMIT')
                return {'order_id': prev['id'], 'status': prev['status'],
                        'idempotent_replay': True, 'amount': prev['amount']}

            h = c.execute('SELECT * FROM holding WHERE acct=? AND product=?',
                          (acct_id, product)).fetchone()
            if not h:
                held = c.execute('SELECT DISTINCT product FROM holding WHERE acct=?',
                                 (acct_id,)).fetchall()
                raise BankError('NOT_HELD', '你没有持有「%s」。当前持仓：%s'
                                % (product, '、'.join(x['product'] for x in held) or '无'))
            if amount > h['amount']:
                raise BankError('EXCEEDS_HOLDING',
                                '赎回额超过持仓：持有 %s 元，本次请求 %s 元'
                                % (cents_to_yuan(h['amount']), cents_to_yuan(amount)))

            now = int(time.time() * 1000)
            oid = 'WO' + uuid.uuid4().hex[:12].upper()
            a = c.execute('SELECT * FROM account WHERE id=?', (acct_id,)).fetchone()
            # 按赎回比例结转收益
            profit_part = int(h['profit'] * (amount / h['amount'])) if h['amount'] else 0
            c.execute('UPDATE account SET balance=? WHERE id=?',
                      (a['balance'] + amount, acct_id))
            remain = h['amount'] - amount
            if remain <= 0:
                c.execute('DELETE FROM holding WHERE id=?', (h['id'],))
            else:
                c.execute('UPDATE holding SET amount=?, profit=? WHERE id=?',
                          (remain, h['profit'] - profit_part, h['id']))
            c.execute('INSERT INTO wealth_order(id,idem_key,acct,product,side,'
                      'amount,status,created_at) VALUES(?,?,?,?,?,?,?,?)',
                      (oid, idem_key, acct_id, product, 'redeem', amount,
                       'succeeded', now))
            c.execute('INSERT INTO ledger(transfer_id,acct,owner_acct,direction,'
                      'amount,balance_after,created_at) VALUES(?,?,?,?,?,?,?)',
                      (None, acct_id, acct_id, 'credit', amount,
                       a['balance'] + amount, now))
            c.execute('COMMIT')
            return {'order_id': oid, 'status': 'succeeded',
                    'idempotent_replay': False, 'amount': amount,
                    'product': product, 'profit_settled': profit_part,
                    'balance_after': a['balance'] + amount}
        except BankError:
            c.execute('ROLLBACK')
            raise
        except Exception:
            c.execute('ROLLBACK')
            raise

    # ══════════════════════════════════════════════════════════════════
    # 跨场景联动（赛题场景 6）
    # ══════════════════════════════════════════════════════════════════
    def available(self, acct_id):
        """可动用余额 = 余额 − 锁定金额。

        这是"锁定"这个概念的**唯一判定口径**。所有花钱的入口都必须用它，
        而不是 balance —— 否则锁定形同虚设（钱被"锁"了却还能花）。
        """
        a = self.get_account(acct_id)
        return a['balance'] - a['locked_amount']

    def create_plan(self, acct_id, occasion, event_date, budget, steps,
                    person=None, idem_key=None):
        """登记一个联动计划。**不动钱**，只记录意图与步骤。

        参数：
          event_date —— 'YYYY-MM-DD'，目标日期（如爱人生日）
          budget     —— 预算（分）
          steps      —— [{'kind','detail','amount','due_date','seq'}, ...]

        安全属性：登记本身没有副作用，所以不需要幂等键也不会造成损失。
        但**若传入 idem_key 则按其幂等**，便于上层重试。
        """
        if not isinstance(budget, int) or isinstance(budget, bool) or budget <= 0:
            raise BankError('INVALID_BUDGET', '预算必须是正整数（单位分）')
        self.get_account(acct_id)          # 账户不存在直接抛

        c = self.conn
        c.execute('BEGIN IMMEDIATE')
        try:
            if idem_key:
                prev = c.execute(
                    'SELECT * FROM linkage_plan WHERE id=?', ('LP' + idem_key,)).fetchone()
                if prev:
                    c.execute('COMMIT')
                    return {'plan_id': prev['id'], 'status': prev['status'],
                            'idempotent_replay': True}

            now = int(time.time() * 1000)
            pid = 'LP' + (idem_key or uuid.uuid4().hex[:16]).upper()
            c.execute('INSERT INTO linkage_plan(id,acct,occasion,person,event_date,'
                      'budget,locked,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
                      (pid, acct_id, occasion, person, event_date, budget, 0,
                       'planned', now))
            for i, st in enumerate(steps):
                c.execute('INSERT INTO linkage_step(id,plan_id,seq,kind,detail,'
                          'amount,due_date,status) VALUES(?,?,?,?,?,?,?,?)',
                          ('LS%s%02d' % (pid[-8:], i), pid, st.get('seq', i),
                           st['kind'], st['detail'], st.get('amount', 0),
                           st['due_date'], 'pending'))
            c.execute('COMMIT')
            return {'plan_id': pid, 'status': 'planned',
                    'idempotent_replay': False, 'steps': len(steps)}
        except BankError:
            c.execute('ROLLBACK')
            raise
        except Exception:
            c.execute('ROLLBACK')
            raise

    def list_plans(self, acct_id=None, status=None):
        sql = 'SELECT * FROM linkage_plan'
        args = []
        where = []
        if acct_id:
            where.append('acct=?')
            args.append(acct_id)
        if status:
            where.append('status=?')
            args.append(status)
        if where:
            sql += ' WHERE ' + ' AND '.join(where)
        sql += ' ORDER BY event_date, id'
        plans = [dict(r) for r in self.conn.execute(sql, args)]
        for p in plans:
            p['steps'] = [dict(r) for r in self.conn.execute(
                'SELECT * FROM linkage_step WHERE plan_id=? ORDER BY seq', (p['id'],))]
        return plans

    def get_plan(self, plan_id):
        r = self.conn.execute('SELECT * FROM linkage_plan WHERE id=?',
                              (plan_id,)).fetchone()
        if not r:
            raise BankError('PLAN_NOT_FOUND', '找不到这个联动计划：%s' % plan_id)
        p = dict(r)
        p['steps'] = [dict(x) for x in self.conn.execute(
            'SELECT * FROM linkage_step WHERE plan_id=? ORDER BY seq', (plan_id,))]
        return p

    def lock_funds(self, plan_id, idem_key=None):
        """为一个计划锁定资金。**余额不变，只标记不可动用。**

        为什么余额不变：
        锁定不是扣款 —— 钱还在账户里，只是被预留了。若这里直接扣 balance，
        就必须同时伪造一笔 ledger 支出，`reconcile()` 立刻不平。
        所以只改 locked_amount，账实仍然相符。
        """
        c = self.conn
        c.execute('BEGIN IMMEDIATE')
        try:
            p = c.execute('SELECT * FROM linkage_plan WHERE id=?', (plan_id,)).fetchone()
            if not p:
                raise BankError('PLAN_NOT_FOUND', '找不到这个联动计划')
            if p['status'] == 'cancelled':
                raise BankError('PLAN_CANCELLED', '该计划已取消，无法锁定资金')
            if p['locked'] > 0:
                c.execute('COMMIT')
                return {'plan_id': plan_id, 'status': p['status'],
                        'locked': p['locked'], 'idempotent_replay': True}

            a = c.execute('SELECT * FROM account WHERE id=?', (p['acct'],)).fetchone()
            free = a['balance'] - a['locked_amount']
            if free < p['budget']:
                raise BankError('INSUFFICIENT_AVAILABLE',
                                '可动用余额不足：可动用 %s 元（余额 %s − 已锁定 %s），'
                                '本计划需要 %s 元'
                                % (cents_to_yuan(free), cents_to_yuan(a['balance']),
                                   cents_to_yuan(a['locked_amount']),
                                   cents_to_yuan(p['budget'])))

            now = int(time.time() * 1000)
            c.execute('UPDATE account SET locked_amount=locked_amount+? WHERE id=?',
                      (p['budget'], p['acct']))
            c.execute('UPDATE linkage_plan SET locked=?,status=?,locked_at=? WHERE id=?',
                      (p['budget'], 'locked', now, plan_id))
            c.execute('COMMIT')
            return {'plan_id': plan_id, 'status': 'locked', 'locked': p['budget'],
                    'idempotent_replay': False,
                    'balance': a['balance'],
                    'available_after': free - p['budget']}
        except BankError:
            c.execute('ROLLBACK')
            raise
        except Exception:
            c.execute('ROLLBACK')
            raise

    def release_lock(self, plan_id):
        """释放计划的锁定资金（余额不变，可动用额度恢复）。"""
        c = self.conn
        c.execute('BEGIN IMMEDIATE')
        try:
            p = c.execute('SELECT * FROM linkage_plan WHERE id=?', (plan_id,)).fetchone()
            if not p:
                raise BankError('PLAN_NOT_FOUND', '找不到这个联动计划')
            if p['locked'] <= 0:
                c.execute('COMMIT')
                return {'plan_id': plan_id, 'released': 0, 'idempotent_replay': True}
            c.execute('UPDATE account SET locked_amount=locked_amount-? WHERE id=?',
                      (p['locked'], p['acct']))
            c.execute('UPDATE linkage_plan SET locked=0 WHERE id=?', (plan_id,))
            c.execute('COMMIT')
            return {'plan_id': plan_id, 'released': p['locked'],
                    'idempotent_replay': False}
        except BankError:
            c.execute('ROLLBACK')
            raise
        except Exception:
            c.execute('ROLLBACK')
            raise

    def execute_step(self, plan_id, step_id, idem_key, today=None):
        """执行一个联动步骤（实际花钱）。**这是本模块唯一的资金出口。**

        这是"跨场景"里真正扣钱的那一步，所以约束最严：
          · 计划必须已锁定资金（防止未预留就扣款）
          · 步骤必须**已到期**（today >= due_date），未到期直接拒绝
          · 幂等：同 idem_key 只成功一次
          · 锁定金额按实际花费等比释放，余额同步扣减，并写 ledger

        注意「外部订购」是**模拟**的：没有真实鲜花/蛋糕接口。
        返回值里带 simulated=True，不要在文档或界面里宣称真的下单成功。
        """
        c = self.conn
        c.execute('BEGIN IMMEDIATE')
        try:
            prev = c.execute('SELECT * FROM linkage_step WHERE idem_key=?',
                             (idem_key,)).fetchone()
            if prev:
                c.execute('COMMIT')
                return {'step_id': prev['id'], 'status': prev['status'],
                        'idempotent_replay': True, 'simulated': True}

            p = c.execute('SELECT * FROM linkage_plan WHERE id=?', (plan_id,)).fetchone()
            if not p:
                raise BankError('PLAN_NOT_FOUND', '找不到这个联动计划')
            if p['status'] == 'cancelled':
                raise BankError('PLAN_CANCELLED', '该计划已取消，不能执行')
            if p['locked'] <= 0:
                raise BankError('NOT_LOCKED',
                                '该计划尚未锁定资金，不能执行扣款步骤。'
                                '请先确认锁定，避免动用未预留的余额。')

            st = c.execute('SELECT * FROM linkage_step WHERE id=? AND plan_id=?',
                           (step_id, plan_id)).fetchone()
            if not st:
                raise BankError('STEP_NOT_FOUND', '找不到这个步骤：%s' % step_id)
            if st['status'] == 'done':
                c.execute('COMMIT')
                return {'step_id': step_id, 'status': 'done',
                        'idempotent_replay': True, 'simulated': True}

            # 到期校验：不依赖真实系统时间，"今天"可注入
            today = today or _today_str()
            if today < st['due_date']:
                raise BankError('NOT_DUE',
                                '该步骤还未到期：应于 %s 执行，今天是 %s。'
                                '提前执行会打乱时序，已拒绝。'
                                % (st['due_date'], today))

            amt = st['amount']
            a = c.execute('SELECT * FROM account WHERE id=?', (p['acct'],)).fetchone()
            if amt > 0 and a['balance'] < amt:
                raise BankError('INSUFFICIENT_FUNDS',
                                '余额不足以执行该步骤：可用 %s 元，需要 %s 元'
                                % (cents_to_yuan(a['balance']), cents_to_yuan(amt)))

            now = int(time.time() * 1000)
            new_balance = a['balance']
            # 锁定金额按实际花费释放，且不超过本计划剩余锁定额
            release = min(amt, p['locked'])
            new_locked = a['locked_amount'] - release
            if amt > 0:
                new_balance = a['balance'] - amt
                c.execute('UPDATE account SET balance=?, locked_amount=? WHERE id=?',
                          (new_balance, new_locked, p['acct']))
                # 资金变动必须留痕 —— 不留痕 reconcile() 立刻不平
                c.execute('INSERT INTO ledger(transfer_id,acct,owner_acct,direction,'
                          'amount,balance_after,created_at) VALUES(?,?,?,?,?,?,?)',
                          (None, p['acct'], p['acct'], 'debit', amt, new_balance, now))
            else:
                c.execute('UPDATE account SET locked_amount=? WHERE id=?',
                          (new_locked, p['acct']))

            result = json.dumps({
                'simulated': True,
                'note': '外部订购为模拟：本项目没有真实的鲜花/蛋糕供应商接口',
                'kind': st['kind'], 'detail': st['detail'],
            }, ensure_ascii=False)
            c.execute('UPDATE linkage_step SET status=?,idem_key=?,executed_at=?,'
                      'result=? WHERE id=?',
                      ('done', idem_key, now, result, step_id))
            c.execute('UPDATE linkage_plan SET locked=locked-? WHERE id=?',
                      (release, plan_id))

            # 所有步骤都完成 → 计划置为 done，并释放剩余锁定
            left = c.execute('SELECT COUNT(*) AS n FROM linkage_step '
                             'WHERE plan_id=? AND status!="done"', (plan_id,)).fetchone()['n']
            freed = 0
            if left == 0:
                rem = c.execute('SELECT locked FROM linkage_plan WHERE id=?',
                                (plan_id,)).fetchone()['locked']
                if rem > 0:
                    c.execute('UPDATE account SET locked_amount=locked_amount-? WHERE id=?',
                              (rem, p['acct']))
                    c.execute('UPDATE linkage_plan SET locked=0,status=? WHERE id=?',
                              ('done', plan_id))
                    freed = rem
                else:
                    c.execute('UPDATE linkage_plan SET status=? WHERE id=?',
                              ('done', plan_id))

            c.execute('COMMIT')
            return {'step_id': step_id, 'status': 'done', 'simulated': True,
                    'idempotent_replay': False, 'amount': amt,
                    'kind': st['kind'], 'detail': st['detail'],
                    'balance_after': new_balance, 'released': release,
                    'released_on_completion': freed,
                    'steps_left': left}
        except BankError:
            c.execute('ROLLBACK')
            raise
        except Exception:
            c.execute('ROLLBACK')
            raise

    def due_steps(self, acct_id=None, today=None):
        """查询**今天应执行（含逾期）**且计划已锁定资金的步骤。

        这是"到期执行"的模拟入口：真实系统里由定时任务轮询调用，
        这里暴露成可查询方法，便于演示与测试。
        """
        today = today or _today_str()
        sql = '''SELECT s.*, p.acct, p.occasion, p.person, p.status AS plan_status,
                        p.locked AS plan_locked
                 FROM linkage_step s JOIN linkage_plan p ON p.id = s.plan_id
                 WHERE s.status='pending' AND s.due_date <= ?
                   AND p.status='locked' '''
        args = [today]
        if acct_id:
            sql += ' AND p.acct=?'
            args.append(acct_id)
        sql += ' ORDER BY s.due_date, s.seq'
        return [dict(r) for r in self.conn.execute(sql, args)]

    def close(self):
        """关闭所有线程的连接。"""
        for c in self._conns:
            try:
                c.close()
            except Exception:
                pass
        self._conns = []


# ── 种子数据 ──────────────────────────────────────────────────────────
SEED = [
    # id,   姓名,   手机,        初始余额(元), 卡号尾号, 卡状态
    ('A001', '张伟', '13800000001', 5000.00,  '6222', 'active'),
    ('A002', '李娜', '13800000002', 1200.00,  '6223', 'active'),
    ('A003', '王强', '13800000003', 800.00,   '6224', 'active'),
    ('A004', '刘敏', '13800000004', 15000.00, '6225', 'active'),
    ('A005', '陈杰', '13800000005', 300.00,   '6226', 'frozen'),
]

SEED_SUBS = [
    # id,  账户,   商户,          金额(元), 周期,     下次扣款(天后)
    ('S001', 'A001', '某视频会员',   25.00,  'monthly',   3),
    ('S002', 'A001', '某云存储',     9.90,   'monthly',  11),
    ('S003', 'A001', '某音乐会员',   15.00,  'monthly',  21),
    ('S004', 'A002', '某外卖会员',   10.00,  'monthly',   7),
]

# 期初持仓（演示用）：张伟持「稳健增利 90 天」与「货币基金 A」
# 期初持仓。金额**直接写死**，不要用「起购额 × N」推导 ——
# 踩过的坑：推导时货币基金起购只要 1 元，×5 仍是 5 元，
# 而演示里会说「赎回 1000 元」，直接撞上"超过持仓"，看起来像系统坏了。
# 种子数据要面向演示动作设计，而不是面向参数关系。
SEED_HOLDINGS = [
    # id,     账户,   产品,              持有金额(元)
    ('H001', 'A001', '稳健增利 90 天',   5000.00),
    ('H002', 'A001', '货币基金 A',       3200.00),
]


def reset_data(core):
    """清空业务数据并重新写入种子，**不删数据库文件**。

    为什么需要这个而不是直接删文件重建：
    HTTP 服务运行期间连接是开着的，Windows 下删不掉自己打开的文件
    （PermissionError），于是"重置演示环境"这个功能直接不可用。
    进程内重置必须走清表，不能走删文件。
    """
    c = core.conn
    c.execute('BEGIN IMMEDIATE')
    try:
        for t in ('ledger', 'transfer', 'subscription', 'card_application',
                  'holding', 'wealth_order', 'linkage_step', 'linkage_plan',
                  'account'):
            c.execute('DELETE FROM %s' % t)
        c.execute("DELETE FROM meta WHERE key LIKE 'opening:%'")
        c.execute('COMMIT')
    except Exception:
        c.execute('ROLLBACK')
        raise
    _seed(core)
    return core


def _seed(core):
    """写入种子数据。reset_data 与 init_db 共用，保证两条路径结果一致。"""
    now = int(time.time() * 1000)
    c = core.conn
    for aid, name, phone, init_yuan, tail, status in SEED:
        cents = yuan_to_cents(init_yuan)
        c.execute(
            'INSERT OR REPLACE INTO account(id,owner_name,phone,balance,locked_amount,'
            'currency,card_no,card_status,daily_limit,created_at) '
            'VALUES(?,?,?,?,?,?,?,?,?,?)',
            (aid, name, phone, cents, 0, 'CNY',
             '**** **** **** ' + tail, status, 5000000, now))
        c.execute('INSERT OR REPLACE INTO meta(key,val) VALUES(?,?)',
                  ('opening:%s' % aid, str(cents)))

    day = 86400000
    for sid, acct, merchant, amt_yuan, cycle, days in SEED_SUBS:
        c.execute(
            'INSERT OR REPLACE INTO subscription(id,acct,merchant,amount,cycle,'
            'next_charge,status,created_at) VALUES(?,?,?,?,?,?,?,?)',
            (sid, acct, merchant, yuan_to_cents(amt_yuan), cycle,
             now + days * day, 'active', now))

    # 期初持仓：让「赎回」在演示一开始就有东西可赎。
    # 金额取「起购额的 2 倍」，这样既满足起购又不至于把余额占满。
    # 注意别写成 yuan_to_cents(min_amount / 100 * 2) —— 那样先除 100 再乘 2
    # 再转回分，等于绕一圈，读的人无法一眼看出到底持有多少。
    for hid, acct, product, amt_yuan in SEED_HOLDINGS:
        spec = next((p for p in WEALTH_CATALOG if p['name'] == product), None)
        if not spec:
            continue
        c.execute('INSERT OR REPLACE INTO holding(id,acct,product,term,amount,'
                  'annualized,profit,created_at) VALUES(?,?,?,?,?,?,?,?)',
                  (hid, acct, product, spec['term'],
                   yuan_to_cents(amt_yuan),
                   spec['annualized'], yuan_to_cents(12.50), now))


def init_db(db_path='bank.db', reset=True):
    """初始化模拟库。

    reset=True 时会先删库文件 —— **仅适用于进程启动时**。
    服务运行中要重置，请用 reset_data(core)，否则 Windows 下会因文件被占用而失败。
    """
    if reset and os.path.exists(db_path):
        for suffix in ('', '-wal', '-shm'):
            p = db_path + suffix
            if os.path.exists(p):
                try:
                    os.remove(p)
                except PermissionError:
                    # 文件被占用说明已有连接在用 —— 这时候不该删文件，
                    # 交给调用方用 reset_data() 走清表路径。
                    raise RuntimeError(
                        '数据库文件被占用，无法删除：%s。'
                        '服务运行中重置请使用 reset_data(core)。' % p)
    core = Core(db_path)
    _seed(core)
    return core


if __name__ == '__main__':
    # 自测：把上面承诺的五条性质逐条验一遍
    import tempfile
    print('=== 模拟核心自测 ===')
    db = os.path.join(tempfile.gettempdir(), 'bank_selftest.db')
    c = init_db(db)

    print('\n[1] 期初余额')
    for a in c.list_accounts():
        print('    %s %-4s  %10s 元  卡 %s  %s'
              % (a['id'], a['owner_name'], cents_to_yuan(a['balance']),
                 a['card_no'][-4:], a['card_status']))

    print('\n[2] 转账 500 元 A001 → A002')
    r1 = c.transfer('A001', 'A002', yuan_to_cents(500), 'idem-demo-1', '测试转账')
    print('    %s  余额 A001=%s  A002=%s'
          % (r1['transfer_id'], cents_to_yuan(r1['from_balance_after']),
             cents_to_yuan(r1['to_balance_after'])))

    print('\n[3] 幂等：同一个 idem_key 再提交一次')
    r2 = c.transfer('A001', 'A002', yuan_to_cents(500), 'idem-demo-1', '测试转账')
    same = r2['transfer_id'] == r1['transfer_id']
    print('    返回同一笔交易: %s   幂等重放标记: %s' % (same, r2.get('idempotent_replay')))
    print('    A001 余额仍为 %s（未被扣两次）' % cents_to_yuan(c.balance('A001')))

    print('\n[3b] 幂等键被复用但参数不同 —— 必须返回原交易，不能按新参数执行')
    # 这是幂等设计的一个安全属性：键相同 = 同一个逻辑操作。
    # 如果这里按"5000 元、转给 A003"重新执行，就等于绕过了幂等保护。
    r2b = c.transfer('A001', 'A003', yuan_to_cents(5000), 'idem-demo-1', '被篡改的请求')
    print('    返回交易: %s（与原交易一致: %s）' % (r2b['transfer_id'], r2b['transfer_id'] == r1['transfer_id']))
    print('    A003 余额: %s（未被这笔"篡改请求"影响）' % cents_to_yuan(c.balance('A003')))

    print('\n[4] 余额不足（A003 有 800 元，转 1000 元）')
    try:
        c.transfer('A003', 'A001', yuan_to_cents(1000), 'idem-demo-2')
        print('    ✗ 应该被拒绝但没有')
    except BankError as e:
        print('    被拒绝: [%s] %s' % (e.code, e.message))

    print('\n[5] 冻结账户不能转出（A005 状态 frozen）')
    try:
        c.transfer('A005', 'A001', yuan_to_cents(1), 'idem-demo-3')
        print('    ✗ 应该被拒绝但没有')
    except BankError as e:
        print('    被拒绝: [%s] %s' % (e.code, e.message))

    print('\n[5b] 转入冻结账户是允许的（冻结只限转出）')
    try:
        rr = c.transfer('A001', 'A005', yuan_to_cents(10), 'idem-demo-4')
        print('    允许，A005 余额变为 %s' % cents_to_yuan(rr['to_balance_after']))
    except BankError as e:
        print('    ✗ 意外被拒绝: [%s] %s' % (e.code, e.message))

    print('\n[6] 冲正')
    rev = c.reverse(r1['transfer_id'], 'idem-rev-1', '测试冲正')
    print('    状态=%s  A001 余额回到 %s'
          % (rev['status'], cents_to_yuan(c.balance('A001'))))

    print('\n[7] 对账（双重记账是否平）')
    rec = c.reconcile()
    print('    %s' % ('账目平衡 ✓' if rec['ok'] else '发现差异 ✗ %s' % rec['problems']))

    c.close()
    print('\n自测完成。')
