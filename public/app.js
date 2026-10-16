/* ==========================================================================
   app.js —— 演示界面逻辑
   无框架、无构建。所有服务端文本插入 DOM 前一律转义 ——
   这些是"数据"，不能当 HTML 处理。
   ========================================================================== */
(function () {
  'use strict';

  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  var SID = 'SDEMO' + Math.random().toString(36).slice(2, 6).toUpperCase();
  var busy = false;
  var pending = null;          // 当前待确认操作（含 op_id / confirm_token）

  /* ── 转义：服务端文本一律当数据 ─────────────────────────────────── */
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  /* 只允许 **粗体** 和 `代码` 两种行内标记，其余全部转义 */
  function rich(s) {
    return esc(s)
      .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\n/g, '<br>');
  }

  function api(path, body) {
    // 静态演示版：mock-api.js 会挂上 window.__API__，
    // 直接调用它而不走 fetch —— 因为本文件是 defer + 同步执行，
    // 会捕获到 fetch 的原始引用，覆写 window.fetch 对它无效。
    if (window.__API__) {
      return Promise.resolve(window.__API__(path, body || {}));
    }
    var opt = { method: body ? 'POST' : 'GET', headers: {} };
    if (body) {
      opt.headers['Content-Type'] = 'application/json';
      opt.body = JSON.stringify(body);
    }
    return fetch(path, opt).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }

  /* ══════════════════ 对话区 ══════════════════ */
  var chat = $('#chat');

  function scrollEnd() { chat.scrollTop = chat.scrollHeight; }

  function bubbleMe(text) {
    var el = document.createElement('div');
    el.className = 'msg msg--me';
    el.innerHTML = '<span class="msg__av">我</span>' +
      '<div class="msg__body"><div class="msg__bubble">' + esc(text) + '</div></div>';
    chat.appendChild(el); scrollEnd();
  }

  function bubbleAI(html, isHtml) {
    var el = document.createElement('div');
    el.className = 'msg msg--ai';
    el.innerHTML = '<span class="msg__av">AI</span>' +
      '<div class="msg__body"><div class="msg__bubble">' +
      (isHtml ? html : rich(html)) + '</div></div>';
    chat.appendChild(el); scrollEnd();
    return el;
  }

  function setBusy(b) {
    busy = b;
    $('#sendBtn').disabled = b;
    $('#input').disabled = b;
  }

  /* ══════════════════ 分级拦截卡 ══════════════════ */
  function renderTierCard(r) {
    var el = document.createElement('div');
    el.className = 'msg msg--ai';
    var tierClass = 'tiercard--' + esc(r.tier);
    var needStrong = r.tier === 'red';

    var reasons = (r.reasons || []).map(function (x) {
      return '<li>' + esc(x) + '</li>';
    }).join('');

    var details = (r.details || []).map(function (d) {
      return '<div class="details__row"><dt>' + esc(d.label) + '</dt>' +
             '<dd>' + esc(d.value) + '</dd></div>';
    }).join('');

    var btns = '<button type="button" class="btn btn--ghost" data-act="cancel">取消</button>';
    if (needStrong) {
      btns += '<button type="button" class="btn btn--danger" data-act="verify">去验证并执行</button>';
    } else {
      btns += '<button type="button" class="btn btn--primary" data-act="confirm">确认执行</button>';
    }

    var tierNote = {
      green: '这类操作没有副作用，Agent 确认意图后直接执行。',
      yellow: '这类操作有副作用，执行前必须让你看清明细并明确同意。',
      red: '这类操作不可逆或涉及资金安全，除确认外还需短信验证码。'
    }[r.tier] || '';

    el.innerHTML =
      '<span class="msg__av">AI</span>' +
      '<div class="msg__body">' +
        '<div class="tiercard ' + tierClass + '" data-op="' + esc(r.op_id) + '">' +
          '<div class="tiercard__head">' +
            '<span class="tiercard__badge">' + esc(r.tier_label) + '</span>' +
            '<span class="tiercard__title">' + esc(r.summary) + '</span>' +
          '</div>' +
          '<div class="tiercard__body">' +
            '<div class="tiercard__why">' +
              '<b>为什么是这一级：</b>' +
              '<ul>' + reasons + '</ul>' +
              '<div style="margin-top:5px;color:var(--ink-3);font-size:11.5px">' +
                esc(tierNote) + '</div>' +
            '</div>' +
            '<dl class="details">' + details + '</dl>' +
            '<div class="tiercard__actions">' + btns + '</div>' +
          '</div>' +
        '</div>' +
      '</div>';

    el.querySelector('[data-act="cancel"]').addEventListener('click', function () {
      api('/api/cancel', { session: SID, op_id: r.op_id }).then(function () {
        bubbleAI('已取消，未执行任何操作。');
        pushStep('cancel', '用户取消', esc(r.summary) + ' —— 已取消，无副作用', 'warn');
      });
      el.querySelector('.tiercard__actions').innerHTML =
        '<span style="font-size:12px;color:var(--ink-3)">已取消</span>';
      pending = null;
    });

    var go = el.querySelector('[data-act="confirm"], [data-act="verify"]');
    go.addEventListener('click', function () {
      if (needStrong) return openOtp(r);
      doExecute(r, null, null, el);
    });

    chat.appendChild(el); scrollEnd();
    return el;
  }

  /* ══════════════════ 执行 ══════════════════ */
  function doExecute(r, challenge, code, cardEl) {
    setBusy(true);
    api('/api/execute', {
      session: SID, op_id: r.op_id, confirm_token: r.confirm_token,
      otp_challenge: challenge, otp_code: code
    }).then(function (res) {
      setBusy(false);
      if (res.type === 'result') {
        bubbleAI(res.message + (res.transaction_id
          ? '\n\n`交易号 ' + res.transaction_id + '`' : ''));
        if (cardEl) lockCard(cardEl, '已执行');
        pushStep('exec', '执行成功', res.message.replace(/\n/g, ' '), 'ok');
        refreshState();
      } else if (res.type === 'tier_escalated') {
        bubbleAI(res.message);
        pushStep('tier', '分级在确认期间上升', (res.reasons || []).join('；'), 'warn');
        renderTierCard(res);
        if (cardEl) lockCard(cardEl, '需重新验证');
      } else if (res.type === 'need_strong_verification') {
        openOtp(r);
      } else {
        var bad = res.message || '执行未完成';
        bubbleAI(bad);
        var kind = (res.locked ? 'bad' : 'warn');
        pushStep(res.locked ? 'breaker' : 'reject', res.locked ? '触发熔断' : '被拒绝', bad, kind);
        if (cardEl) lockCard(cardEl, '已拒绝');
      }
    }).catch(function (e) {
      setBusy(false);
      bubbleAI('请求失败：' + e.message);
    });
  }

  function lockCard(cardEl, text) {
    var act = cardEl.querySelector('.tiercard__actions');
    if (act) act.innerHTML = '<span style="font-size:12px;color:var(--ink-3)">' +
      esc(text) + '</span>';
  }

  /* ══════════════════ 强验证弹窗 ══════════════════ */
  var modal = $('#otpModal');
  var otpTarget = null;
  var otpChallenge = null;

  function openOtp(r) {
    otpTarget = r;
    $('#otpErr').textContent = '';
    $('#otpInput').value = '';
    $('#otpDemo').textContent = '------';
    modal.hidden = false;

    api('/api/verify/request', { session: SID, op_id: r.op_id, confirm_token: r.confirm_token })
      .then(function (res) {
        if (res.type === 'otp_sent') {
          otpChallenge = res.challenge;     // 提交时要用，必须存下来
          $('#otpDemo').textContent = res.demo_code;
          $('#otpPhone').textContent = '****0001';
          $('#otpInput').focus();
          pushStep('verify', '已下发短信验证码',
                   '红色级别操作，等待用户输入验证码', 'warn');
        } else {
          $('#otpErr').textContent = res.message || '无法获取验证码';
        }
      }).catch(function (e) { $('#otpErr').textContent = '获取验证码失败：' + e.message; });
  }

  function closeOtp() { modal.hidden = true; otpTarget = null; }

  $('#otpCancel').addEventListener('click', function () {
    closeOtp();
    pushStep('cancel', '用户取消强验证', '操作未执行', 'warn');
  });

  $('#otpSubmit').addEventListener('click', function () {
    if (!otpTarget) return;
    var code = $('#otpInput').value.trim();
    if (!/^\d{6}$/.test(code)) { $('#otpErr').textContent = '请输入 6 位数字验证码'; return; }
    var target = otpTarget;
    var card = chat.querySelector('.tiercard[data-op="' + target.op_id + '"]');
    closeOtp();
    setBusy(true);

    api('/api/execute', {
      session: SID, op_id: target.op_id, confirm_token: target.confirm_token,
      otp_challenge: otpChallenge, otp_code: code
    }).then(function (res) {
      setBusy(false);
      if (res.type === 'result') {
        bubbleAI(res.message + (res.transaction_id
          ? '\n\n`交易号 ' + res.transaction_id + '`' : ''));
        if (card) { var c = card.closest('.msg'); if (c) lockCard(c, '已执行'); }
        pushStep('verify', '强验证通过', '短信验证码校验成功', 'ok');
        pushStep('exec', '执行成功', res.message.replace(/\n/g, ' '), 'ok');
        refreshState();
      } else {
        // 验证码错误 —— 关键：确认凭证仍有效，可直接重试，不用重新发起
        bubbleAI(res.message + (res.retryable
          ? '\n\n（确认凭证仍然有效，你可以直接再输一次验证码，**不需要重新发起**。）' : ''));
        pushStep('reject', res.locked ? '触发熔断' : '验证失败',
                 res.message, res.locked ? 'bad' : 'warn');
        if (res.retryable && !res.locked) {
          // 复用同一个 challenge 重新打开弹窗（不重新下发，避免刷短信）
          otpTarget = target;
          modal.hidden = false;
          $('#otpErr').textContent = res.message || '';
          $('#otpInput').value = '';
          $('#otpInput').focus();
        }
      }
    }).catch(function (e) { setBusy(false); bubbleAI('请求失败：' + e.message); });
  });

  /* ══════════════════ 决策链路面板 ══════════════════ */
  var paneDecision = $('#paneDecision');
  var stepSeq = 0;

  function pushStep(kind, title, detail, level) {
    var empty = paneDecision.querySelector('.empty');
    if (empty) empty.remove();
    stepSeq++;
    var el = document.createElement('div');
    el.className = 'step' + (level ? ' step--' + level : '');
    el.innerHTML =
      '<span class="step__n">' + stepSeq + '</span>' +
      '<div>' +
        '<div class="step__t">' + esc(title) +
          '<span class="step__time">' + new Date().toLocaleTimeString('zh-CN', { hour12: false }) + '</span>' +
        '</div>' +
        '<div class="step__d">' + detail + '</div>' +
      '</div>';
    paneDecision.appendChild(el);
    paneDecision.scrollTop = paneDecision.scrollHeight;
  }

  /* ══════════════════ 主流程 ══════════════════ */
  function send(text) {
    text = String(text || '').trim();
    if (!text || busy) return;
    bubbleMe(text);
    $('#input').value = '';
    setBusy(true);

    api('/api/chat', { session: SID, text: text }).then(function (r) {
      setBusy(false);

      // 意图识别 —— 无条件先展示，让评委看到"它听懂了吗"
      // 注意：意图名在 r.intent.intent，不是 r.type（r.type 是响应类型）。
      // 之前这里错把 r.type 当意图显示，界面上出现"识别为 confirm_required"这种胡话。
      var it = r.intent || {};
      pushStep('intent', '意图识别',
        '识别为 <code>' + esc(it.intent || '—') + '</code>' +
        (it.confidence ? '，置信度 ' + (it.confidence * 100).toFixed(0) + '%' : '') +
        (it.slots && Object.keys(it.slots).length
          ? '<br>槽位：<code>' + esc(JSON.stringify(it.slots)) + '</code>' : ''),
        'ok');

      if (r.type === 'result') {
        bubbleAI(r.message);
        pushStep('exec', '绿色级别 · 自动执行',
          '纯查询操作，无副作用，无需二次确认', 'ok');
      } else if (r.type === 'confirm_required') {
        pushStep('tier', '分级判定：' + esc(r.tier_label),
          (r.reasons || []).map(esc).join('<br>'), r.tier === 'red' ? 'bad' : 'warn');
        renderTierCard(r);
      } else if (r.type === 'blocked') {
        bubbleAI(r.message);
        pushStep('breaker', '熔断拦截', esc(r.message), 'bad');
      } else if (r.type === 'refused') {
        bubbleAI(r.message);
        pushStep('reject', '已拒绝', esc(r.message), 'bad');
      } else {
        bubbleAI(r.message || '（无回复）');
        pushStep('clarify', '需要补充信息', esc(r.message || ''), 'warn');
      }
    }).catch(function (e) {
      setBusy(false);
      bubbleAI('请求失败：' + e.message);
    });
  }

  /* ══════════════════ 状态刷新 ══════════════════ */
  function money(v) {
    return Number(v).toLocaleString('zh-CN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }

  function refreshState() {
    return api('/api/state').then(function (s) {
      var a = s.accounts[0];
      $('#userName').textContent = a.owner;
      $('#avatar').textContent = a.owner.charAt(0);
      $('#cardNo').textContent = a.card_no;
      $('#balance').textContent = money(a.balance / 100);
      $('#dailyLimit').textContent = money(a.daily_limit / 100);
      var st = $('#cardStatus');
      st.textContent = a.card_status_text;
      st.className = 'chip ' + (a.card_status === 'active' ? 'chip--ok'
        : a.card_status === 'frozen' ? 'chip--warn' : 'chip--bad');
    });
  }

  /* ══════════════════ 审计面板 ══════════════════ */
  function refreshAudit() {
    return api('/api/audit').then(function (a) {
      $('#chainDot').className = 'dot ' + (a.chain_ok ? 'dot--ok' : 'dot--bad');
      $('#chainText').textContent = a.chain_ok
        ? '审计链完整 · ' + a.stats.total + ' 条'
        : '审计链异常！' + a.chain_message;

      var parts = [];
      for (var k in a.stats.by_event) parts.push(k + '=' + a.stats.by_event[k]);
      $('#auditStats').textContent = parts.join('  ');

      var list = $('#auditList');
      list.innerHTML = a.entries.slice().reverse().map(function (e) {
        var key = e.event.split('.')[0];
        var detail = '';
        var f = e.fields || {};
        if (f.text) detail = f.text;
        else if (f.action) detail = f.action + (f.tier ? ' → ' + f.tier : '');
        else if (f.reason) detail = f.reason;
        else if (f.message) detail = f.message;
        else if (f.code) detail = f.code;
        else detail = JSON.stringify(f).slice(0, 90);
        return '<li>' +
          '<span class="audit__seq">#' + e.seq + '</span>' +
          '<span class="audit__ev" data-k="' + esc(key) + '">' + esc(e.event) + '</span>' +
          '<span class="audit__f" title="' + esc(detail) + '">' + esc(detail) + '</span>' +
          '<span class="audit__h">' + esc(e.hash) + '</span>' +
        '</li>';
      }).join('');
    });
  }

  /* ══════════════════ 分级规则面板 ══════════════════ */
  function loadRules() {
    return api('/api/catalog').then(function (c) {
      var order = ['green', 'yellow', 'red'];
      var policy = {
        green: '自动执行 · 无副作用，Agent 确认意图后直接执行',
        yellow: '用户确认 · 执行前展示明细并获得明确同意',
        red: '强验证 · 确认 + 短信验证码（多因子）'
      };
      $('#rulesList').innerHTML = order.map(function (t) {
        var items = (c.tiers[t] || []).map(function (x) {
          return '<span class="rule__item" title="' + esc(x.action) + '">' +
                 esc(x.desc) + '</span>';
        }).join('');
        return '<div class="rule rule--' + t + '">' +
          '<div class="rule__head">' +
            '<span class="rule__badge">' + esc(c.labels[t]) + '</span>' +
            '<span class="rule__policy">' + esc(policy[t]) + '</span>' +
          '</div>' +
          '<div class="rule__list">' + items + '</div>' +
        '</div>';
      }).join('');
    });
  }

  /* ══════════════════ 标签切换 ══════════════════ */
  $$('.tab').forEach(function (tab) {
    tab.addEventListener('click', function () {
      $$('.tab').forEach(function (t) { t.classList.toggle('is-on', t === tab); });
      var name = tab.getAttribute('data-tab');
      $$('.pane').forEach(function (p) {
        p.classList.toggle('is-on', p.getAttribute('data-pane') === name);
      });
      if (name === 'audit') refreshAudit();
    });
  });

  /* ══════════════════ 事件绑定 ══════════════════ */
  $('#composer').addEventListener('submit', function (e) {
    e.preventDefault();
    send($('#input').value);
  });

  $$('.quick__chip').forEach(function (b) {
    b.addEventListener('click', function () { send(b.getAttribute('data-say')); });
  });

  $('#resetBtn').addEventListener('click', function () {
    api('/api/reset', {}).then(function (r) {
      bubbleAI(r.message);
      stepSeq = 0;
      paneDecision.innerHTML =
        '<p class="empty">演示环境已重置。左侧发起一次对话，' +
        '这里会实时显示：意图识别 → 分级判定 → 凭证校验 → 执行结果。</p>';
      refreshState(); refreshAudit();
    });
  });

  $('#otpInput').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); $('#otpSubmit').click(); }
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !modal.hidden) closeOtp();
  });

  /* ══════════════════ 启动 ══════════════════ */
  refreshState();
  refreshAudit();
  loadRules();
  setInterval(refreshAudit, 4000);      // 审计面板定期自动刷新

  bubbleAI('你好，我是你的银行智能助手。\n\n' +
    '你可以直接说需求，比如「给李娜转 500 元」。\n' +
    '涉及资金的操作，我会先给你一份明细，确认后才执行；' +
    '**大额操作还需要短信验证**。');
})();
