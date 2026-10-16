#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api_server.py —— 演示原型的 HTTP 接口（零依赖）

职责很窄：把已经写好、已经自测通过的模块暴露成 HTTP 接口，不做任何业务判断。
**所有安全判定都在 agent/ 与 security/ 里，本文件不参与任何权限决策。**
这条边界很重要：接口层一旦开始"顺手判断一下风险"，安全逻辑就有两个真相来源。

启动：
    python api_server.py            # 默认 8090
    python api_server.py --port 9000
"""

import argparse
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bank.core import Core, init_db, reset_data, cents_to_yuan, BankError
from security.permissions import ConfirmationStore, CircuitBreaker, TIER_LABEL, ACTIONS
from security.audit import AuditLog
from agent.orchestrator import AgentSession, WEALTH_PRODUCTS

ROOT = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(ROOT, 'web')
DB_PATH = os.path.join(ROOT, 'demo_bank.db')
AUDIT_PATH = os.path.join(ROOT, 'audit.log')

# ── 全局状态（单进程演示够用；生产要放共享存储）────────────────────────
_lock = threading.Lock()
_core = None
_audit = None
_sessions = {}          # session_id -> AgentSession

MAX_BODY = 256 * 1024


def boot(reset_db=True):
    """初始化模拟核心与会话容器。"""
    global _core, _audit
    _core = init_db(DB_PATH, reset=reset_db)
    # 每次启动清空审计文件，避免演示时混入历史记录
    if os.path.exists(AUDIT_PATH):
        os.remove(AUDIT_PATH)
    _audit = AuditLog(AUDIT_PATH)
    _audit.append('system.boot', note='演示环境启动', schema=1)
    _sessions.clear()


def get_session(sid):
    with _lock:
        s = _sessions.get(sid)
        if not s:
            s = AgentSession(_core, _audit, _confirms, _breaker, session_id=sid)
            _sessions[sid] = s
        return s


_confirms = ConfirmationStore(ttl_seconds=180)
_breaker = CircuitBreaker(max_failures=3, window_seconds=300, lock_seconds=600)


# ══════════════════════════════════════════════════════════════════════
# 序列化：把内部结构转成前端好用的形状
# ══════════════════════════════════════════════════════════════════════
def fmt_account(a):
    return {
        'id': a['id'],
        'owner': a['owner_name'],
        'phone': (a['phone'][:3] + '****' + a['phone'][-4:]) if a.get('phone') else None,
        'balance': a['balance'],
        'balance_text': cents_to_yuan(a['balance']),
        'card_no': a['card_no'],
        'card_status': a['card_status'],
        'card_status_text': {'active': '正常', 'frozen': '已冻结', 'lost': '已挂失'}
                             .get(a['card_status'], a['card_status']),
        'daily_limit': a['daily_limit'],
        'daily_limit_text': cents_to_yuan(a['daily_limit']),
    }


def fmt_json(obj):
    """递归把分转成可读文本，并处理 sqlite Row。"""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[k] = fmt_json(v)
        # 常见金额字段补一个文本版本，前端不用自己除 100
        for k in ('amount', 'balance', 'total', 'per_person', 'daily_limit',
                  'next_charge', 'limit', 'profit', 'min_amount'):
            if k in out and isinstance(out[k], int):
                out[k + '_text'] = cents_to_yuan(out[k])
        return out
    if isinstance(obj, (list, tuple)):
        return [fmt_json(x) for x in obj]
    if isinstance(obj, float):
        return round(obj, 6)
    return obj


# ══════════════════════════════════════════════════════════════════════
# HTTP
# ══════════════════════════════════════════════════════════════════════
class Handler(BaseHTTPRequestHandler):
    server_version = 'BankAgent/1.0'
    # 显式声明 1.1：这样 Content-Length 之外的响应也能正常收尾，
    # 并且 keep-alive 行为可预期。默认 1.0 会在某些客户端上表现为"连接被关闭"。
    protocol_version = 'HTTP/1.1'

    # ── 工具 ──────────────────────────────────────────────────────────
    def _json(self, obj, status=200):
        try:
            body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        except (TypeError, ValueError) as exc:
            # 序列化失败不能把连接掐掉，要让客户端拿到一个可读的错误
            sys.stderr.write('!! JSON 序列化失败: %s\n' % exc)
            body = json.dumps({'error': '响应序列化失败', 'code': 'SERIALIZE'},
                              ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass          # 客户端提前断开，正常现象，不是错误

    def _read_body(self):
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            return {}

    def _static(self, path):
        rel = 'index.html' if path in ('/', '') else path.lstrip('/')
        full = os.path.normpath(os.path.join(WEB_DIR, rel))
        # 防目录穿越：必须仍在 WEB_DIR 内
        if not full.startswith(WEB_DIR):
            self.send_error(403)
            return
        if not os.path.isfile(full):
            self.send_error(404)
            return
        ext = os.path.splitext(full)[1].lower()
        ctype = {'.html': 'text/html; charset=utf-8',
                 '.css': 'text/css; charset=utf-8',
                 '.js': 'text/javascript; charset=utf-8',
                 '.svg': 'image/svg+xml',
                 '.png': 'image/png'}.get(ext, 'application/octet-stream')
        with open(full, 'rb') as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write('  %s  %s\n' % (time.strftime('%H:%M:%S'), fmt % args))

    def handle_one_request(self):
        """吞掉"客户端提前断开"的噪音。

        socketserver 默认会给 ConnectionResetError / ConnectionAbortedError
        打一整段 traceback。这些是浏览器正常行为（关标签页、切换页面、
        CDP 截图后立刻关闭连接），不是错误。演示时满屏红字会误导观众，
        也让人以为系统不稳定。
        """
        try:
            super().handle_one_request()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            self.close_connection = True

    # ── GET ───────────────────────────────────────────────────────────
    def do_GET(self):
        path = self.path.split('?')[0]
        try:
            if path == '/api/state':
                return self._api_state()
            if path == '/api/audit':
                return self._api_audit()
            if path == '/api/catalog':
                return self._api_catalog()
            return self._static(path)
        except Exception as exc:                       # noqa: BLE001
            sys.stderr.write('!! GET %s 未捕获异常: %r\n' % (path, exc))
            import traceback
            traceback.print_exc()
            try:
                self._json({'error': '服务内部错误', 'code': 'INTERNAL',
                            'detail': str(exc)}, 200)
            except Exception:
                pass

    # ── POST ──────────────────────────────────────────────────────────
    def do_POST(self):
        path = self.path.split('?')[0]
        body = self._read_body()
        try:
            if path == '/api/chat':
                return self._api_chat(body)
            if path == '/api/execute':
                return self._api_execute(body)
            if path == '/api/verify/request':
                return self._api_verify_request(body)
            if path == '/api/cancel':
                return self._api_cancel(body)
            if path == '/api/reset':
                return self._api_reset(body)
            self._json({'error': '未知接口：%s' % path}, 404)
        except BankError as exc:
            self._json({'error': exc.message, 'code': exc.code}, 200)
        except Exception as exc:                       # noqa: BLE001
            # 不把栈信息给前端 —— 内部实现细节不外泄
            sys.stderr.write('!! 未捕获异常 %s: %s\n' % (path, exc))
            self._json({'error': '服务内部错误', 'code': 'INTERNAL'}, 200)

    # ── 接口实现 ──────────────────────────────────────────────────────
    def _api_state(self):
        """首页要的全量状态：账户、订阅、持仓、产品。"""
        accts = [fmt_account(a) for a in _core.list_accounts()]
        subs = [dict(r) for r in _core.conn.execute(
            'SELECT * FROM subscription WHERE status="active" ORDER BY next_charge')]
        rec = _core.reconcile()
        self._json({
            'accounts': accts,
            'subscriptions': fmt_json(subs),
            'products': fmt_json(WEALTH_PRODUCTS),
            'holdings': fmt_json([
                {'name': '稳健增利 90 天', 'amount': 2000000, 'annualized': 0.031, 'profit': 51230},
                {'name': '货币基金 A', 'amount': 500000, 'annualized': 0.018, 'profit': 9250},
            ]),
            'reconcile': rec,
            'server_time': int(time.time() * 1000),
        })

    def _api_catalog(self):
        """操作清单 —— 答辩时用来展示"哪些动作是绿/黄/红"。"""
        tier = {'green': [], 'yellow': [], 'red': []}
        for name, spec in ACTIONS.items():
            tier[spec['tier']].append({'action': name, 'desc': spec['desc']})
        self._json({
            'tiers': tier,
            'labels': TIER_LABEL,
            'rules': {
                'small_transfer_cap': 100000,
                'small_transfer_cap_text': '1000.00',
                'note': '单笔或当日累计超过 1000 元即升为红色，需短信验证',
            },
        })

    def _api_chat(self, body):
        sid = (body.get('session') or '').strip() or ('S' + uuid.uuid4().hex[:8].upper())
        text = (body.get('text') or '').strip()
        if not text:
            return self._json({'error': '缺少 text'}, 200)

        sess = get_session(sid)
        started = time.time()
        result = sess.propose(text)
        result['session'] = sid
        result['elapsed_ms'] = int((time.time() - started) * 1000)
        # 让前端能显示"分级规则说明"，而不是只看到一个颜色
        if result.get('tier'):
            result['tier_color'] = {'green': 'green', 'yellow': 'yellow', 'red': 'red'}[result['tier']]
        return self._json(fmt_json(result))

    def _api_execute(self, body):
        sid = body.get('session')
        if not sid:
            return self._json({'error': '缺少 session'}, 200)
        sess = get_session(sid)
        r = sess.execute(body.get('op_id'), body.get('confirm_token'),
                         body.get('otp_challenge'), body.get('otp_code'))
        r['session'] = sid
        return self._json(fmt_json(r))

    def _api_verify_request(self, body):
        sid = body.get('session')
        if not sid:
            return self._json({'error': '缺少 session'}, 200)
        sess = get_session(sid)
        r = sess.request_strong_verification(body.get('op_id'), body.get('confirm_token'))
        r['session'] = sid
        return self._json(fmt_json(r))

    def _api_cancel(self, body):
        """用户主动放弃一个待确认操作。"""
        sid = body.get('session')
        sess = _sessions.get(sid)
        if sess:
            op = sess.pending.pop(body.get('op_id'), None)
            if op:
                _audit.append('confirm.cancelled', session_id=sid, op=body.get('op_id'))
        return self._json({'ok': True})

    def _api_audit(self):
        ok, msg, idx = _audit.verify_chain()
        entries = _audit.entries(limit=120)
        # 给前端看的审计条目：把 params 里的敏感字段处理干净
        view = []
        for e in entries:
            f = dict(e.get('fields') or {})
            view.append({
                'seq': e['seq'],
                'at': e['at'],
                'event': e['event'],
                'session': e.get('session'),
                'hash': e['hash'][:12],
                'prev': e['prev'][:12],
                'fields': f,
            })
        self._json({
            'chain_ok': ok,
            'chain_message': msg,
            'bad_index': idx,
            'stats': _audit.stats(),
            'entries': view,
        })

    def _api_reset(self, body):
        """重置演示环境。

        注意走 reset_data（清表）而不是 boot()（删文件）——
        服务运行期间数据库文件是打开的，Windows 下删不掉。
        这是一个真实踩过的坑：原先这里调 boot(reset_db=True)，
        表现是"点重置没反应"。
        """
        with _lock:
            reset_data(_core)
            _sessions.clear()
            _confirms._store.clear()
            _confirms._otp.clear()
            _breaker._fail.clear()
            _breaker._locked.clear()
        _audit.append('system.reset', note='演示环境已重置')
        return self._json({'ok': True, 'message': '演示环境已重置：账户余额与订阅恢复初始状态'})


def main():
    ap = argparse.ArgumentParser(description='银行 AI 智能体 · 演示原型')
    ap.add_argument('--port', type=int, default=8090)
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--keep', action='store_true', help='保留上次的数据库')
    args = ap.parse_args()

    # ── 端口独占：必须关掉 allow_reuse_address ───────────────────────
    # 这是一个真实踩过的坑。http.server.HTTPServer 默认
    # allow_reuse_address = 1，在 Windows 上允许**同一端口绑两次**：
    # 第二个实例不报错、照常打印启动横幅，你会以为它起来了；
    # 而 Get-NetTCPConnection 按端口查只显示一个 PID，
    # 所以按端口排查会得出"只有一个进程"的错误结论。
    #
    # 后果不只是"多发一个请求"。两个进程会**同时持有 demo_bank.db 句柄**，
    # 于是后续启动时的 init_db(reset=True) 删文件失败，
    # 报一个看起来毫无头绪的 PermissionError: 数据库文件被占用。
    # 我排查这个报错花了不少时间，根因就在这里。
    #
    # SO_REUSEADDR 在 Unix 上的语义是"重用 TIME_WAIT 状态的端口"（有用），
    # 但在 Windows 上它还允许"抢占已绑定的端口"（危险）。
    # 演示服务需要的是独占而不是抢占，所以关掉它，让端口冲突立刻报错。
    ThreadingHTTPServer.allow_reuse_address = False

    try:
        srv = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        print('\n  ✗ 无法绑定 %s:%d —— %s' % (args.host, args.port, exc))
        print('    这个端口已被占用。可能是上次的服务没退干净，'
              '先用下面的命令找出来：\n')
        print('      Get-NetTCPConnection -LocalPort %d -State Listen |'
              ' Select-Object OwningProcess' % args.port)
        print('      Get-Process -Id <上面查到的PID>\n')
        print('    或者直接换一个端口：python api_server.py --port 8099\n')
        return 1

    # 绑定后才写库：先把端口抢到手，避免"库被重置了但服务起不来"
    boot(reset_db=not args.keep)

    # 0.0.0.0 表示监听所有网卡，它自己不是可用地址 ——
    # 打印 127.0.0.1 会把局域网演示的人引到错误的地址上。
    if args.host == '0.0.0.0':
        local_ip = _detect_lan_ip()
        shown = local_ip or '127.0.0.1'
        extra = '  （局域网其他设备访问用这个地址）'
    else:
        shown = args.host
        extra = ''
    url = 'http://%s:%d/' % (shown, args.port)
    print('''
  ┌────────────────────────────────────────────────────┐
  │  银行 AI 智能体 · 演示原型                          │
  │                                                    │
  │  %-48s  │
  │                                                    │
  │  权限分级：绿=自动 · 黄=确认 · 红=短信强验证         │
  │  Ctrl+C 停止                                       │
  └────────────────────────────────────────────────────┘
''' % url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\n  已停止。\n')
    finally:
        srv.server_close()


if __name__ == '__main__':
    main()
