#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit.py —— 操作审计日志（哈希链防篡改）

赛题要求「所有关键操作需记录完整的决策链路与执行日志」。

但"记日志"有个常被忽略的问题：**日志本身可以被改。**
如果攻击者能拿到写权限，删掉或改写自己的痕迹，那审计就是摆设。

所以这里不用普通的 append-only 日志，而是**哈希链**：
    这条记录的 hash = H(上一条的 hash + 本条内容)
任何一条被改动，它之后的所有 hash 都对不上，一验就露。

真实金融系统的审计要更强（WORM 存储、异地实时同步、独立权限域），
哈希链是单机环境下能做到的、最低成本的可验证防篡改。
"""

import hashlib
import json
import threading
import time

GENESIS = '0' * 64


class AuditLog:
    """哈希链审计日志。

    每条记录存：序号、时间、会话、事件类型、内容、前一条 hash、本条 hash。
    verify_chain() 可以随时校验整条链是否被篡改过。
    """

    def __init__(self, path=None):
        self._lock = threading.Lock()
        self._entries = []
        self._path = path
        if path:
            self._load()

    # ── 写 ─────────────────────────────────────────────────────────────
    def append(self, event, session_id=None, **fields):
        """追加一条审计记录。

        返回本条记录的 hash（可回传给前端做"收据"）。
        """
        with self._lock:
            prev = self._entries[-1]['hash'] if self._entries else GENESIS
            seq = len(self._entries)
            body = {
                'seq': seq,
                'at': int(time.time() * 1000),
                'event': event,
                'session': session_id,
                'fields': fields,
                'prev': prev,
            }
            body['hash'] = self._digest(body)
            self._entries.append(body)
            if self._path:
                with open(self._path, 'a', encoding='utf-8') as fh:
                    fh.write(json.dumps(body, ensure_ascii=False) + '\n')
            return body['hash']

    @staticmethod
    def _digest(body):
        canonical = json.dumps(
            {k: v for k, v in body.items() if k != 'hash'},
            sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

    # ── 校验 ───────────────────────────────────────────────────────────
    def verify_chain(self):
        """逐条重算 hash。返回 (ok, 说明, 首个出问题的序号)。"""
        prev = GENESIS
        for i, e in enumerate(self._entries):
            if e['prev'] != prev:
                return False, '第 %d 条记录的前序哈希不匹配（记录被删除或插入）' % i, i
            if self._digest(e) != e['hash']:
                return False, '第 %d 条记录的内容被修改过' % i, i
            prev = e['hash']
        return True, '哈希链完整，共 %d 条记录' % len(self._entries), None

    # ── 读 ─────────────────────────────────────────────────────────────
    def entries(self, limit=None, event=None, session_id=None):
        rows = self._entries
        if event:
            rows = [r for r in rows if r['event'] == event]
        if session_id:
            rows = [r for r in rows if r['session'] == session_id]
        if limit:
            rows = rows[-limit:]
        return list(rows)

    def decision_chain(self, session_id, limit=50):
        """还原某个会话的完整决策链路 —— 答辩时用来证明"每一步都有据可查"。

        链路里会包含：意图解析结果、分级判定及理由、确认/验证过程、
        执行结果或拒绝原因。这正是赛题要的"完整决策链路"。
        """
        return [r for r in self.entries(session_id=session_id, limit=limit)
                if r['event'].startswith(('intent.', 'tier.', 'confirm.', 'verify.',
                                          'exec.', 'guard.', 'breaker.'))]

    def _load(self):
        try:
            with open(self._path, encoding='utf-8') as fh:
                self._entries = [json.loads(l) for l in fh if l.strip()]
        except FileNotFoundError:
            self._entries = []

    def stats(self):
        by_event = {}
        for e in self._entries:
            by_event[e['event']] = by_event.get(e['event'], 0) + 1
        return {'total': len(self._entries), 'by_event': by_event}


if __name__ == '__main__':
    import os
    import tempfile

    print('=== 审计日志自测 ===')
    log = AuditLog()

    print('\n[1] 记录一次完整的决策链路')
    h1 = log.append('intent.parsed', session_id='s1', text='给李娜转500',
                    intent='transfer', slots={'to': '李娜', 'amount': 50000}, confidence=0.92)
    h2 = log.append('tier.checked', session_id='s1', action='transfer.small',
                    tier='yellow', reasons=['今日已转出 0.00 元，本笔后累计 500.00 元，在小额上限内'])
    h3 = log.append('confirm.issued', session_id='s1', token_prefix=h2[:8])
    h4 = log.append('confirm.verified', session_id='s1', ok=True)
    h5 = log.append('exec.succeeded', session_id='s1', transfer_id='TXABC123',
                    amount=50000, from_acct='A001', to_acct='A002')
    print('    写入 5 条，末条 hash = %s…' % h5[:16])

    print('\n[2] 校验链完整性')
    ok, msg, idx = log.verify_chain()
    print('    %s  %s' % (ok, msg))

    print('\n[3] 决策链路还原')
    for r in log.decision_chain('s1'):
        print('    #%-2d %-18s %s' % (r['seq'], r['event'],
                                      json.dumps(r['fields'], ensure_ascii=False)[:78]))

    print('\n[4] 篡改测试：偷偷改一条记录的内容')
    log._entries[3]['fields']['ok'] = False     # 把"验证通过"改成"验证失败"
    ok2, msg2, idx2 = log.verify_chain()
    print('    校验结果: %s' % ok2)
    print('    定位到:   %s' % msg2)
    print('    （若用普通日志，这一改就查不出来了）')

    print('\n[5] 删除测试：删掉中间一条')
    log2 = AuditLog()
    for i in range(5):
        log2.append('exec.succeeded', session_id='s2', n=i)
    del log2._entries[2]
    ok3, msg3, _ = log2.verify_chain()
    print('    校验结果: %s' % ok3)
    print('    定位到:   %s' % msg3)

    print('\n[6] 统计')
    print('    %s' % json.dumps(log2.stats(), ensure_ascii=False))

    print('\n自测完成。')
