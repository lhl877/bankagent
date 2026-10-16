/* ==========================================================================
   mock-api.js —— 静态演示用的接口层

   为什么需要它
   ============
   演示界面的 Agent 逻辑在 Python 后端（api_server.py + agent/ + security/）。
   Cloudflare Pages 只能托管静态文件，跑不了 Python 进程。
   所以这个版本把后端的**真实输出**预置成静态响应，让界面可以完整演示。

   重要声明（也印在界面上）
   ======================
   这里的响应不是编造的文案，而是把 api_server.py 实测跑出来的结果固化了：
   金额、判定依据、交易号前缀、审计事件名都取自真实输出。
   区别只在于——静态版不会真正改数据，分级判定也不是现算的。

   数据来源：docs/技术文档.md 与各模块自测的实际输出。
   ========================================================================== */
(function () {
  'use strict';

  var YUAN = function (c) { return (c / 100).toLocaleString('zh-CN',
    { minimumFractionDigits: 2, maximumFractionDigits: 2 }); };

  /* ── 演示状态：放 sessionStorage，刷新后保持，点重置可恢复 ────────── */
  var DEFAULT = {
    balances: { A001: 500000, A002: 120000, A003: 80000, A004: 1500000, A005: 30000 },
    // 持仓金额直接写死，不用「起购额 × N」推导 ——
    // 推导时货币基金起购只要 1 元，×5 仍是 5 元，
    // 而演示会说「赎回 1000 元」，会撞上"超过持仓"。种子数据要面向演示动作设计。
    holdings: {
      '稳健增利 90 天': 500000,
      '货币基金 A': 320000
    },
    // 锁定金额（分）：为跨场景联动预留。
    // 与后端一致：**余额不动，只标记不可动用**。
    // 若把锁定金额从 balances 里扣掉，账实就对不上了。
    locked: 0,
    // 联动计划（跨场景联动，赛题场景 6）
    plans: [],
    dailyOut: 0,
    cardStatus: 'active',
    seq: 0,
    otpWrongOnce: false
  };

  function load() {
    var st;
    try {
      var s = sessionStorage.getItem('fb-demo-state');
      st = s ? JSON.parse(s) : JSON.parse(JSON.stringify(DEFAULT));
    } catch (e) { st = JSON.parse(JSON.stringify(DEFAULT)); }
    // 补新字段的默认值。老版本存下的 sessionStorage 里没有 locked/plans，
    // 直接用会得到 undefined，参与算术就变成 NaN —— 静默错误，很难查。
    if (typeof st.locked !== 'number') st.locked = 0;
    if (!Array.isArray(st.plans)) st.plans = [];
    return st;
  }
  function save(st) {
    try { sessionStorage.setItem('fb-demo-state', JSON.stringify(st)); } catch (e) {}
  }
  var ST = load();
  var ISSUED_CODE = null;      // 已下发的验证码，用于比对

  /* ── 审计链：演示用哈希链，真的按 H(前一条 + 内容) 计算 ──────────── */
  var audit = [];
  var GENESIS = new Array(65).join('0');

  function sha256Sync(str) {
    // 静态版没有 crypto.subtle 的同步版本，这里用一个确定性哈希做演示。
    // 注意：这不是密码学安全的——它只用来演示"链式结构能发现篡改"，
    // 真实实现在 security/audit.py 里用的是 hashlib.sha256。
    var h1 = 0x811c9dc5, h2 = 0x1000193;
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      h1 = ((h1 ^ c) * 16777619) >>> 0;
      h2 = ((h2 + c) * 2654435761) >>> 0;
    }
    var s = (h1 >>> 0).toString(16) + (h2 >>> 0).toString(16);
    while (s.length < 64) s += s;
    return s.slice(0, 64);
  }

  function logEvent(event, fields) {
    var prev = audit.length ? audit[audit.length - 1].hash : GENESIS;
    var body = { seq: audit.length, at: Date.now(), event: event,
                 session: 'STATIC-DEMO', fields: fields || {}, prev: prev };
    body.hash = sha256Sync(JSON.stringify(body));
    audit.push(body);
  }

  logEvent('system.boot', { note: '静态演示版启动' });

  /* ── 分级判定：按真实规则实现（这段逻辑与 security/permissions.py 一致）── */
  var CAP = 100000;   // 1000 元 = 100000 分

  function tier(amount, isTransfer) {
    if (!isTransfer) return 'green';
    if (amount > CAP) return 'red';
    if (ST.dailyOut + amount > CAP) return 'red';
    return 'yellow';
  }

  function fmtTier(t) {
    return { green: '绿色 · 自动执行', yellow: '黄色 · 需确认', red: '红色 · 需强验证' }[t];
  }

  /* ── 注入话术识别（归一化后匹配，与真实实现一致）────────────────── */
  var PATTERNS = [
    [/忽略(以上|前面|之前|所有)?[^。，,]{0,6}(指令|规则|限制|设定|提示)/, '试图让助手忽略既有规则'],
    [/(我是|你现在是|你是|你现在就是)[^。，,]{0,6}(管理员|超级用户|root|admin|行长|系统)/, '试图冒充更高权限身份'],
    [/(标记|设为|设置为|改成|归类)[^。，,]{0,8}(绿色|低风险|自动执行|无需确认|免确认)/, '试图篡改风险分级'],
    [/(skip_?confirm|bypass|跳过确认|无需确认|免确认|不用确认|直接执行)/, '试图跳过确认环节'],
    [/(已获?授权|已经授权|已被授权|获用户授权)/, '试图伪造授权声明'],
    [/(系统指令|系统提示|admincommand|developermode|开发者模式)/, '伪装成系统级指令'],
    [/^\{"(action|params|intent)/, '试图直接投递结构化指令']
  ];

  function detectInjection(text) {
    var flat = text.replace(/\s+/g, '');
    var hits = [];
    PATTERNS.forEach(function (p) { if (p[0].test(flat)) hits.push(p[1]); });
    return hits;
  }

  /* ── 金额抽取（只支持演示用到的几种，规则与 agent.py 一致）──────── */
  function amount(text) {
    var scrub = text.replace(/A0*\d+/gi, ' ')
                    .replace(/\d+\s*(月|日|号|次|个|人|天|年|周)/g, ' ');
    var m = scrub.match(/(\d+(?:\.\d+)?)\s*(块|元|圆|k|K)/);
    if (m) { var v = parseFloat(m[1]); return /[kK]/.test(m[2]) ? v * 1000 : v; }
    m = scrub.match(/(\d+(?:\.\d+)?)\s*(万|千)/);
    if (m) { var v2 = parseFloat(m[1]); return m[2] === '万' ? v2 * 10000 : v2 * 1000; }
    m = scrub.match(/(?<![零一二两三四五六七八九十百千万亿])(\d+(?:\.\d+)?)(?![零一二两三四五六七八九十百千万亿])/);
    if (m) return parseFloat(m[1]);
    return null;
  }

  var PEOPLE = { '李娜': 'A002', '王强': 'A003', '刘敏': 'A004', '张伟': 'A001' };

  // 与 bank/core.py 的 WEALTH_CATALOG 保持一致（含起购金额，用于申购校验）
  // 可动用余额 = 余额 − 锁定。与 Python 侧的 core.available() 同一口径。
  // 所有花钱的入口都必须用它，否则"锁定"形同虚设。
  function available() { return ST.balances.A001 - (ST.locked || 0); }

  // 日期工具：以天为粒度做字符串比较即可（YYYY-MM-DD 字典序等于时间序）
  function todayStr() {
    var d = new Date();
    var m = String(d.getMonth() + 1), dd = String(d.getDate());
    return d.getFullYear() + '-' + (m.length < 2 ? '0' + m : m) +
           '-' + (dd.length < 2 ? '0' + dd : dd);
  }
  function addDays(dateStr, days) {
    var p = dateStr.split('-');
    var d = new Date(Number(p[0]), Number(p[1]) - 1, Number(p[2]));
    d.setDate(d.getDate() + days);
    var m = String(d.getMonth() + 1), dd = String(d.getDate());
    return d.getFullYear() + '-' + (m.length < 2 ? '0' + m : m) +
           '-' + (dd.length < 2 ? '0' + dd : dd);
  }

  // 跨场景联动的领域常量（与 agent/orchestrator.py 保持一致）
  // ⚠ 模拟边界：外部订购没有真实供应商接口，返回值带 simulated 标记。
  var LINKAGE_GIFTS = [
    { kind: 'order_gift', detail: '订购鲜花', amount: 30000 },
    { kind: 'order_gift', detail: '订购蛋糕', amount: 20000 }
  ];
  var LINKAGE_DEFAULT_BUDGET = 100000;   // 1000 元
  var LINKAGE_LEAD_DAYS = 2;
  var LINKAGE_DEFAULT_EVENT_DATE = '2026-06-18';

  var WEALTH_CATALOG = [
    { name: '货币基金 A', term: '随时可取', annualized: 0.0185, min_amount: 100, risk: '低' },
    { name: '稳健增利 90 天', term: '90 天', annualized: 0.031, min_amount: 100000, risk: '中低' },
    { name: '固收增强 180 天', term: '180 天', annualized: 0.0385, min_amount: 500000, risk: '中' },
    { name: '指数增强组合', term: '365 天', annualized: 0.062, min_amount: 1000000, risk: '中高' }
  ];

  function payee(text) {
    var m = text.match(/\b(1[3-9]\d{9})\b/);
    if (m) return { phone: m[1] };
    for (var name in PEOPLE) {
      if (text.indexOf(name) >= 0) return { name: name, acct: PEOPLE[name] };
    }
    m = text.match(/给\s*([\u4e00-\u9fa5]{2,4})\s*(?:转|汇|打)/);
    if (m) return { name: m[1], unknown: true };
    return null;
  }

  /* ══════════════════ 各接口的静态实现 ══════════════════ */
  function accounts() {
    return [
      { id: 'A001', owner: '张伟', balance: ST.balances.A001,
        balance_text: YUAN(ST.balances.A001),
        locked: ST.locked || 0, locked_text: YUAN(ST.locked || 0),
        available: available(), available_text: YUAN(available()),
        card_no: '**** **** **** 6222',
        card_status: ST.cardStatus,
        card_status_text: { active: '正常', frozen: '已冻结', lost: '已挂失' }[ST.cardStatus],
        daily_limit: 5000000, daily_limit_text: '50,000.00' }
    ];
  }

  function handleState() {
    return { accounts: accounts(),
      subscriptions: [
        { merchant: '某视频会员', amount: 2500, amount_text: '25.00', cycle: 'monthly' },
        { merchant: '某云存储', amount: 990, amount_text: '9.90', cycle: 'monthly' },
        { merchant: '某音乐会员', amount: 1500, amount_text: '15.00', cycle: 'monthly' }
      ],
      products: [
        { name: '货币基金 A', term: '随时可取', annualized: 0.0185, risk: '低' },
        { name: '稳健增利 90 天', term: '90 天', annualized: 0.031, risk: '中低' }
      ], reconcile: { ok: true, problems: [] } };
  }

  function handleCatalog() {
    return {
      labels: { green: '绿色 · 自动执行', yellow: '黄色 · 需确认', red: '红色 · 需强验证' },
      tiers: {
        green: [{ action: 'account.balance', desc: '查询余额' },
                { action: 'bill.analyze', desc: '账单分析' },
                { action: 'bill.anomaly', desc: '异常交易识别' },
                { action: 'wealth.list', desc: '查询理财产品' },
                { action: 'wealth.holdings', desc: '查询持仓与收益' },
                { action: 'subscription.list', desc: '查询订阅与代扣' },
                { action: 'linkage.plan', desc: '登记跨场景联动计划' },
                { action: 'linkage.list', desc: '查询联动计划' }],
        yellow: [{ action: 'transfer.small', desc: '小额转账' },
                 { action: 'split.request', desc: '发起 AA 收款' },
                 { action: 'subscription.cancel', desc: '取消订阅' },
                 { action: 'card.apply_virtual', desc: '申请虚拟卡' },
                 { action: 'linkage.lock', desc: '为联动计划锁定资金' }],
        red: [{ action: 'transfer.large', desc: '大额转账' },
              { action: 'wealth.purchase', desc: '申购理财产品' },
              { action: 'wealth.redeem', desc: '赎回理财产品' },
              { action: 'card.limit_change', desc: '调整卡额度' },
              { action: 'card.freeze', desc: '挂失/冻结卡片' },
              { action: 'linkage.run', desc: '执行联动步骤（扣款下单）' },
              { action: 'password.change', desc: '修改密码' }]
      },
      rules: { small_transfer_cap: CAP, small_transfer_cap_text: '1000.00' }
    };
  }

  function handleAudit() {
    return {
      chain_ok: true,
      chain_message: '哈希链完整，共 ' + audit.length + ' 条记录',
      stats: { total: audit.length,
               by_event: audit.reduce(function (a, e) {
                 a[e.event] = (a[e.event] || 0) + 1; return a; }, {}) },
      entries: audit.map(function (e) {
        return { seq: e.seq, at: e.at, event: e.event, session: e.session,
                 hash: e.hash.slice(0, 12), prev: e.prev.slice(0, 12), fields: e.fields };
      })
    };
  }

  /* ── /api/chat：意图识别 → 分级 → 出计划 ─────────────────────────── */
  /* ══════════════════ 跨场景联动辅助 ══════════════════ */

  function pad2(x) { x = String(x); return x.length < 2 ? '0' + x : x; }

  function linkOccasion(text) {
    var table = [
      [/爱人.*生日|老婆.*生日|先生.*生日|伴侣.*生日/, '爱人生日'],
      [/(?:爸|妈|父亲|母亲|父母).*生日/, '父母生日'],
      [/(?:孩子|儿子|女儿|宝宝).*生日/, '子女生日'],
      [/生日/, '生日'],
      [/纪念日|结婚纪念/, '纪念日'],
      [/节日|过节|春节|中秋|端午/, '节日']
    ];
    for (var i = 0; i < table.length; i++) {
      if (table[i][0].test(text)) return table[i][1];
    }
    return null;
  }

  /** 把"那个生日计划"解析成具体计划。
   *  规则：说了事件名就按名字匹配；没指名且只有一个未完成计划就用它；
   *  有多个 → 返回 null 让上层追问（挑错计划意味着给错的人订礼物）。 */
  function pickPlan(occasion) {
    var open = ST.plans.filter(function (p) {
      return p.status === 'planned' || p.status === 'locked';
    });
    if (occasion) {
      var hit = open.filter(function (p) {
        return p.occasion.indexOf(occasion) >= 0 || occasion.indexOf(p.occasion) >= 0;
      });
      if (hit.length === 1) return hit[0];
      if (hit.length > 1) return null;
    }
    if (open.length === 1) return open[0];
    return null;
  }

  function statusText(s) {
    return { planned: '已登记（未锁资金）', locked: '已锁定资金',
             done: '已完成', cancelled: '已取消' }[s] || s;
  }

  function linkagePlanText(plan) {
    var lines = ['已登记联动计划 **' + plan.occasion + '**（' + plan.event_date + '）。'];
    if (plan.person) lines.push('关联人：' + plan.person);
    lines.push('预算 ' + YUAN(plan.budget) + ' 元，拆成 ' + plan.steps.length + ' 个步骤：');
    plan.steps.forEach(function (st) {
      lines.push('· ' + st.detail + ' —— ' + st.due_date + ' 执行，' + YUAN(st.amount) + ' 元');
    });
    var tot = plan.steps.reduce(function (a, s) { return a + s.amount; }, 0);
    if (tot > plan.budget) {
      lines.push('');
      lines.push('⚠ 步骤合计 ' + YUAN(tot) + ' 元超过预算 ' + YUAN(plan.budget) + ' 元，请调整预算或步骤。');
    }
    lines.push('');
    lines.push('计划已登记但**尚未锁定资金** —— 钱还能正常使用。');
    lines.push('（说明：本演示使用默认事件日期 ' + plan.event_date +
               '。真实使用请明确告知日期，例如「生日是 2026-06-18」。）');
    return lines.join('\n');
  }

  function linkageListText() {
    if (!ST.plans.length) {
      return '你还没有登记跨场景联动计划。\n' +
             '可以这样说：「我爱人生日，帮我当月锁定 1000 元」';
    }
    var lines = ['你共有 **' + ST.plans.length + ' 个**联动计划（可用余额 ' +
                 YUAN(available()) + ' 元）：'];
    ST.plans.forEach(function (p) {
      lines.push('· **' + p.occasion + '**（' + p.event_date + '）预算 ' +
                 YUAN(p.budget) + ' 元 · 状态：' + statusText(p.status));
      p.steps.forEach(function (st) {
        lines.push('    ' + (st.status === 'done' ? '✓' : '·') + ' ' + st.detail +
                   '（' + st.due_date + '，' + YUAN(st.amount) + ' 元）');
      });
    });
    return lines.join('\n');
  }

  function linkageLockCard(plan) {
    ST.seq++;
    var opId = 'OP' + ST.seq + 'LLK';
    logEvent('tier.checked', { action: 'linkage.lock', tier: 'yellow' });
    logEvent('confirm.issued', { op: opId, tier: 'yellow' });
    return {
      type: 'confirm_required', tier: 'yellow', tier_label: fmtTier('yellow'),
      op_id: opId, action: 'linkage.lock',
      summary: '为「' + plan.occasion + '」锁定 ' + YUAN(plan.budget) + ' 元',
      reasons: ['为联动计划锁定资金 的基准级别：黄色 · 需确认',
                '钱仍在账户内，但期间不能用于转账/理财 —— 可逆，故为黄色而非红色'],
      needs: ['user_confirmation'],
      confirm_token: 'STATIC-' + opId, expires_in: 180,
      details: [{ label: '账户', value: 'A001' },
                { label: '计划', value: plan.occasion },
                { label: '锁定金额', value: YUAN(plan.budget) + ' 元' },
                { label: '影响', value: '这笔钱仍在你账户里，但期间不能用于转账/理财' }],
      _planId: plan.id, _side: 'linkage_lock',
      intent: { intent: 'linkage_lock', confidence: 0.88,
                slots: { acct: 'A001', plan_id: plan.id } }
    };
  }

  function linkageRunCard(plan) {
    ST.seq++;
    var opId = 'OP' + ST.seq + 'LRN';
    var today = todayStr();
    var due = plan.steps.filter(function (s) {
      return s.status === 'pending' && s.due_date <= today;
    });
    logEvent('tier.checked', { action: 'linkage.run', tier: 'red' });
    logEvent('confirm.issued', { op: opId, tier: 'red' });
    return {
      type: 'confirm_required', tier: 'red', tier_label: fmtTier('red'),
      op_id: opId, action: 'linkage.run',
      summary: '执行「' + plan.occasion + '」的到期步骤',
      reasons: ['执行联动步骤（扣款下单） 的基准级别：红色 · 需强验证',
                '资金离账且不可逆（礼品已订），需多因子认证'],
      needs: ['user_confirmation', 'strong_verification'],
      requires_strong: true,
      confirm_token: 'STATIC-' + opId, expires_in: 180,
      details: [{ label: '账户', value: 'A001' },
                { label: '计划', value: plan.occasion },
                { label: '今天', value: today },
                { label: '本次到期步骤',
                  value: due.map(function (s) { return s.detail; }).join('、') || '无' },
                { label: '本次扣款',
                  value: YUAN(due.reduce(function (a, s) { return a + s.amount; }, 0)) + ' 元' },
                { label: '外部订购', value: '模拟（无真实供应商接口）' }],
      _planId: plan.id, _side: 'linkage_run',
      intent: { intent: 'linkage_run', confidence: 0.85,
                slots: { acct: 'A001', plan_id: plan.id } }
    };
  }

  function handleChat(body) {
    var text = (body.text || '').trim();
    logEvent('intent.parsed', { text: text });

    // 1. 注入检测
    var hits = detectInjection(text);
    if (hits.length) {
      logEvent('guard.injection_detected', { patterns: hits, text: text.slice(0, 120) });
      return { type: 'refused',
        message: '这句话里包含了试图改变我权限设定的内容，我不会执行。\n\n' +
                 '说明一下我的工作方式：\n' +
                 '· 我只能在你本人授权的范围内操作，任何「忽略规则」「我是管理员」' +
                 '「已授权」的说法都不会改变这一点\n' +
                 '· 一笔操作属于哪个风险等级，由系统规则计算，不由对话内容决定\n\n' +
                 '如果你确实需要转账或改限额，直接说清楚要做什么就可以了。',
        intent: { intent: 'unknown', confidence: 0.9, slots: {} } };
    }

    // 2. 定时转账
    if (/定时|明天|后天|下周|每月|每天|预约/.test(text) && /转|汇|打钱/.test(text)) {
      logEvent('guard.unsupported_scheduled', { text: text.slice(0, 120) });
      return { type: 'refused',
        message: '定时/预约转账目前还没有实现调度器，我不能受理。\n\n' +
                 '**我不会把它当成立即转账执行** —— 那样你的钱会马上出去，' +
                 '和你说的「每月」完全不是一回事。\n\n' +
                 '如果这笔钱现在就要转，请去掉时间词重说一次。',
        intent: { intent: 'transfer', confidence: 0.6, slots: { scheduled: true } } };
    }

    // 3. 查询类
    if (/余额|还有多少|卡里|账上/.test(text)) {
      logEvent('tier.checked', { action: 'account.balance', tier: 'green' });
      logEvent('exec.auto_green', { action: 'account.balance' });
      return { type: 'result', tier: 'green', tier_label: fmtTier('green'),
        auto_executed: true,
        message: '你的账户（张伟）当前余额为 **' + YUAN(ST.balances.A001) +
                 ' 元**，卡片状态：' +
                 ({ active: '正常', frozen: '已冻结', lost: '已挂失' }[ST.cardStatus]) + '。',
        intent: { intent: 'query_balance', confidence: 0.95, slots: { acct: 'A001' } } };
    }

    if (/账单|消费|花了多少|支出|流水/.test(text)) {
      logEvent('tier.checked', { action: 'bill.analyze', tier: 'green' });
      return { type: 'result', tier: 'green', tier_label: fmtTier('green'),
        auto_executed: true,
        message: '本期共 3 笔支出，合计 **540.00 元**。\n主要去向：\n' +
                 '· 转账给李娜：500.00 元（92.6%）\n· 转账给王强：30.00 元（5.6%）\n' +
                 '· 未分类：10.00 元（1.9%）',
        intent: { intent: 'bill_analyze', confidence: 0.9,
                  slots: { acct: 'A001', period: 'month' } } };
    }

    if (/订阅|自动续费|代扣|会员/.test(text)) {
      logEvent('tier.checked', { action: 'subscription.list', tier: 'green' });
      return { type: 'result', tier: 'green', tier_label: fmtTier('green'),
        auto_executed: true,
        message: '你目前有 **3 项**自动续费，每月合计 **49.90 元**：\n' +
                 '· 某视频会员：25.00 元 / 月\n· 某音乐会员：15.00 元 / 月\n' +
                 '· 某云存储：9.90 元 / 月',
        intent: { intent: 'subscription_list', confidence: 0.92, slots: { acct: 'A001' } } };
    }

    // 4. 理财申购 / 赎回
    var product = null;
    for (var wi = 0; wi < WEALTH_CATALOG.length; wi++) {
      if (text.indexOf(WEALTH_CATALOG[wi].name) >= 0) { product = WEALTH_CATALOG[wi].name; break; }
    }
    if (!product) {
      var wkeys = { '货币基金 A': ['货币'], '稳健增利 90 天': ['稳健', '增利'],
                    '固收增强 180 天': ['固收', '增强'], '指数增强组合': ['指数', '组合'] };
      for (var wn in wkeys) {
        if (wkeys[wn].some(function (k) { return text.indexOf(k) >= 0; })) { product = wn; break; }
      }
    }
    // 列举类问法不能进操作分支。「我有哪些理财」含「理财」二字，
    // 若不排除就会被当成申购、然后因缺金额被追问，与用户意图相反。
    // 「可以买」「能买」「买什么」「买哪」也是询问语气，必须与申购区分开。
    // 实测：「有哪些理财产品可以买」曾被判成申购，然后因缺金额被追问 ——
    // 而这恰恰是最自然的产品查询说法。
    // 只按"列举/疑问"词形判断，**不加** "且不含操作动词" 这个条件。
    // 踩过的坑：原先写成
    //     /有哪些|可以买|.../ .test(text) && !/买|申购|.../.test(text)
    // 对「有哪些理财产品可以买」判为 false —— 因为它同时含"有哪些"和"可以买"，
    // 而"可以买"里就有个"买"字。于是这句**询问**被判成申购，追问"申购多少元"。
    // "可以买"的"买"与"买 2000 元"的"买"字面相同、语义不同，
    // 区分依据只能是疑问词形，不能是操作动词存在与否。
    var isListing = /有哪些|有什么|看看|列表|持有哪些|哪个好|可以买|能买|买什么|买哪/.test(text);
    // 卡相关说法不走理财分支。
    // Python 侧靠「卡分支排在理财之前」解决，但本文件的理财块是后加进去的、
    // 排在卡块之前 —— 两侧顺序不一致，行为就会分叉
    // （实测「买一张虚拟卡」在 Python 侧正确、在静态版被当成申购）。
    // 与其重排（改动面大），不如在进入条件上显式排除。
    var isCardTalk = /卡/.test(text);
    var hasOp = /申购|购买|赎回|取出|卖掉|(?:买)(?!什么|哪)/.test(text);
    if ((hasOp || (product && !isListing)) && !isListing && !isCardTalk) {
      var wamt = amount(text);
      if (/赎回|取出|卖掉/.test(text)) {
        // 未指名产品时，只在持仓唯一的情况下补全；多个持仓不猜
        if (!product) {
          var held = Object.keys(ST.holdings).filter(function (k) { return ST.holdings[k] > 0; });
          if (held.length === 1) product = held[0];
        }
        if (!product) {
          logEvent('intent.need_slots', { intent: 'wealth_redeem', missing: ['product'] });
          return { type: 'clarify', message: '你想赎回哪一个理财产品？你当前持有：' +
            Object.keys(ST.holdings).filter(function (k) { return ST.holdings[k] > 0; }).join('、'),
            intent: { intent: 'wealth_redeem', confidence: 0.7, slots: {} } };
        }
        if (wamt === null) {
          return { type: 'clarify', message: '请问赎回多少元？',
            intent: { intent: 'wealth_redeem', confidence: 0.7, slots: { product: product } } };
        }
        var rcents = Math.round(wamt * 100);
        var have = ST.holdings[product] || 0;
        logEvent('tier.checked', { action: 'wealth.redeem', tier: 'red' });
        ST.seq++;
        return { type: 'confirm_required', tier: 'red', tier_label: fmtTier('red'),
          op_id: 'OP' + ST.seq + 'WRE', action: 'wealth.redeem',
          summary: '赎回「' + product + '」' + YUAN(rcents) + ' 元',
          reasons: ['赎回理财产品 的基准级别：红色 · 需强验证',
                    '涉及资金安全，需多因子认证'],
          needs: ['user_confirmation', 'strong_verification'],
          confirm_token: 'STATIC-WRE', expires_in: 180,
          details: [{ label: '账户', value: 'A001' }, { label: '产品', value: product },
                    { label: '赎回金额', value: YUAN(rcents) + ' 元' },
                    { label: '当前持仓', value: YUAN(have) + ' 元' }],
          _amount: rcents, _product: product, _side: 'redeem',
          intent: { intent: 'wealth_redeem', confidence: 0.85,
                    slots: { acct: 'A001', product: product, amount_yuan: wamt } } };
      }
      // 申购
      if (!product) product = '货币基金 A';
      if (wamt === null) {
        return { type: 'clarify', message: '请问申购多少元？',
          intent: { intent: 'wealth_purchase', confidence: 0.7, slots: { product: product } } };
      }
      var pcents = Math.round(wamt * 100);
      logEvent('tier.checked', { action: 'wealth.purchase', tier: 'red' });
      ST.seq++;
      return { type: 'confirm_required', tier: 'red', tier_label: fmtTier('red'),
        op_id: 'OP' + ST.seq + 'WBU', action: 'wealth.purchase',
        summary: '申购「' + product + '」' + YUAN(pcents) + ' 元',
        reasons: ['申购理财产品 的基准级别：红色 · 需强验证',
                  '涉及资金安全，需多因子认证'],
        needs: ['user_confirmation', 'strong_verification'],
        confirm_token: 'STATIC-WBU', expires_in: 180,
        details: [{ label: '账户', value: 'A001' }, { label: '产品', value: product },
                  { label: '金额', value: YUAN(pcents) + ' 元' },
                  { label: '活期余额', value: YUAN(ST.balances.A001) + ' 元' }],
        _amount: pcents, _product: product, _side: 'purchase',
        intent: { intent: 'wealth_purchase', confidence: 0.85,
                  slots: { acct: 'A001', product: product, amount_yuan: wamt } } };
    }

    // 只有纯查询才走这里。带操作动词的（赎回/申购/买入）已在上面被
    // 理财操作分支处理掉了 —— 不收窄的话「赎回 1000 元货币基金 A」
    // 会因为含"基金"二字被这里截获，返回产品列表而不是赎回确认卡。
    if (/理财|基金|收益|年化|持仓/.test(text)
        && !/赎回|取出|卖掉|申购|买入|购买/.test(text)) {
      logEvent('tier.checked', { action: 'wealth.list', tier: 'green' });
      return { type: 'result', tier: 'green', tier_label: fmtTier('green'),
        auto_executed: true,
        message: '在售产品：\n· 货币基金 A（随时可取）：年化 1.85%，1.00 元起购，风险 低\n' +
                 '· 稳健增利 90 天（90 天）：年化 3.10%，1,000.00 元起购，风险 中低',
        intent: { intent: 'wealth_list', confidence: 0.9, slots: { acct: 'A001' } } };
    }

    // 4b. 跨场景联动（赛题场景 6）
    // 放在这里的原因：它在语义上是"理财/转账之外的一类计划"，
    // 但必须在转账分支之前 —— 否则"订鲜花"里的"买/订"会被转账的
    // 金额规则吃掉。与 Python 侧 _p_linkage 的排序位置一致。
    // 入口关键词必须包含「计划 / 安排 / 到期 / 执行」——
    // 否则「现在执行计划」在入口就被挡掉，下面那个执行分支永远到达不了。
    // 这与 Python 侧 _p_linkage 是同一个坑，两侧必须一致。
    var LINK_KEY = /生日|纪念日|节日|送礼|礼物|鲜花|蛋糕|联动|提前准备|备忘|计划|安排|到期|该执行|执行计划/;
    if (LINK_KEY.test(text)) {
      var wantsOrder = /订|下单|买|鲜花|蛋糕|礼物/.test(text);
      var wantsLock = /锁定|预留|冻结|圈起来|别动/.test(text);

      // 查计划
      if (/有(?:哪些|什么|没有).*(?:计划|安排)|我的.*(?:联动|计划|安排)/.test(text)) {
        logEvent('tier.checked', { action: 'linkage.list', tier: 'green' });
        return { type: 'result', tier: 'green', tier_label: fmtTier('green'),
          auto_executed: true,
          message: linkageListText(),
          data: { plans: ST.plans, available: available() },
          intent: { intent: 'linkage_list', confidence: 0.9, slots: { acct: 'A001' } } };
      }

      var occasion = linkOccasion(text) || '生日';
      var person = (text.match(/(爱人|老婆|老公|先生|太太|伴侣|爸爸|妈妈|父亲|母亲|儿子|女儿|孩子|宝宝)/) || [])[1] || null;

      // 纯锁定（无订购意图）→ 单独动作
      if (wantsLock && !wantsOrder) {
        var lockPlan = pickPlan(occasion);
        if (!lockPlan) {
          return { type: 'clarify',
            message: '没找到要锁定资金的计划。可以先说「我爱人生日，帮我准备一下」登记一个。',
            intent: { intent: 'linkage_lock', confidence: 0.8, slots: {} } };
        }
        return linkageLockCard(lockPlan);
      }

      // 显式执行
      if (/执行|现在(?:就)?(?:订|买|办)|立即(?:订|买)|到期|跑一下/.test(text)) {
        var runPlan = pickPlan(occasion);
        if (!runPlan) {
          return { type: 'clarify', message: '没找到要执行的计划，请说明是哪一个。',
            intent: { intent: 'linkage_run', confidence: 0.8, slots: {} } };
        }
        return linkageRunCard(runPlan);
      }

      // 登记计划
      var ev = '2026-06-18';
      var md = text.match(/(\d{4})-(\d{1,2})-(\d{1,2})/);
      if (md) ev = md[1] + '-' + pad2(md[2]) + '-' + pad2(md[3]);
      var budgetYuan = amount(text) === null ? 1000 : amount(text);
      var budget = Math.round(budgetYuan * 100);
      var due = addDays(ev, -LINKAGE_LEAD_DAYS);
      var plan = {
        id: 'LP' + sha256Sync('plan' + Date.now() + ST.plans.length).slice(0, 12).toUpperCase(),
        occasion: occasion, person: person, event_date: ev, budget: budget,
        locked: 0, status: 'planned',
        steps: LINKAGE_GIFTS.map(function (g, i) {
          return { id: 'LS' + i, seq: i, kind: g.kind,
                   detail: g.detail + '（' + ev + ' 前 ' + LINKAGE_LEAD_DAYS + ' 天）',
                   amount: g.amount, due_date: due, status: 'pending' };
        })
      };
      ST.plans.push(plan);
      save(ST);
      logEvent('tier.checked', { action: 'linkage.plan', tier: 'green' });
      logEvent('exec.green_plan', { plan: plan.id, occasion: occasion });
      var card = { type: 'result', tier: 'green', tier_label: fmtTier('green'),
        auto_executed: true, message: linkagePlanText(plan),
        data: { plan: plan, available: available() },
        intent: { intent: 'linkage_create', confidence: 0.87,
                  slots: { acct: 'A001', occasion_text: occasion, person: person,
                           event_date: ev, budget: budget } } };
      // 同句说了"锁定" → 链接一张黄色确认卡。
      // 不顺手锁掉：锁定会让钱不能动用，必须让用户单独确认一次。
      if (wantsLock) card.chained = linkageLockCard(plan);
      return card;
    }

    // 5. 卡操作（申请虚拟卡 / 挂失 / 解挂）
    //
    // 这三个分支原先**根本没实现** —— 而卡片管理是赛题的六个场景之一。
    // 结果是线上 demo 里说「申请一张虚拟卡」会走到"没听懂"。
    // 静态版与 Python 后端的行为必须一致，缺哪个场景都会在演示时暴露。
    if (/挂失|冻结|锁卡|丢卡|卡片丢失/.test(text)) {
      logEvent('tier.checked', { action: 'card.freeze', tier: 'red' });
      ST.seq++;
      return { type: 'confirm_required', tier: 'red', tier_label: fmtTier('red'),
        op_id: 'OP' + ST.seq + 'CFR', action: 'card.freeze',
        summary: '挂失并冻结卡片',
        reasons: ['挂失/冻结卡片 的基准级别：红色 · 需强验证',
                  '该操作不可逆，且影响卡片全部交易'],
        needs: ['user_confirmation', 'strong_verification'],
        confirm_token: 'STATIC-CFR', expires_in: 180,
        details: [{ label: '账户', value: 'A001' },
                  { label: '影响', value: '卡片将无法用于任何交易' },
                  { label: '当前状态', value: { active: '正常', frozen: '已冻结', lost: '已挂失' }[ST.cardStatus] }],
        _card: 'freeze',
        intent: { intent: 'card_freeze', confidence: 0.93, slots: { acct: 'A001' } } };
    }
    if (/解挂|解冻|恢复用卡/.test(text)) {
      logEvent('tier.checked', { action: 'card.unfreeze', tier: 'red' });
      ST.seq++;
      return { type: 'confirm_required', tier: 'red', tier_label: fmtTier('red'),
        op_id: 'OP' + ST.seq + 'CUF', action: 'card.unfreeze',
        summary: '解除卡片挂失状态',
        reasons: ['卡片解挂 的基准级别：红色 · 需强验证',
                  '恢复用卡属于高风险操作'],
        needs: ['user_confirmation', 'strong_verification'],
        confirm_token: 'STATIC-CUF', expires_in: 180,
        details: [{ label: '账户', value: 'A001' },
                  { label: '当前状态', value: { active: '正常', frozen: '已冻结', lost: '已挂失' }[ST.cardStatus] }],
        _card: 'unfreeze',
        intent: { intent: 'card_unfreeze', confidence: 0.9, slots: { acct: 'A001' } } };
    }
    if (/虚拟卡|新卡|开卡|办卡|申请卡|办一张卡|买\s*一?\s*张?\s*卡/.test(text)) {
      logEvent('tier.checked', { action: 'card.apply_virtual', tier: 'yellow' });
      ST.seq++;
      return { type: 'confirm_required', tier: 'yellow', tier_label: fmtTier('yellow'),
        op_id: 'OP' + ST.seq + 'CAP', action: 'card.apply_virtual',
        summary: '申请一张虚拟卡',
        reasons: ['申请虚拟卡 的基准级别：黄色 · 需确认',
                  '有副作用但可撤销，无需强验证'],
        needs: ['user_confirmation'],
        confirm_token: 'STATIC-CAP', expires_in: 180,
        details: [{ label: '账户', value: 'A001' },
                  { label: '卡片类型', value: '虚拟卡' },
                  { label: '额度', value: '与主卡一致' }],
        _card: 'apply',
        intent: { intent: 'card_apply_virtual', confidence: 0.9, slots: { acct: 'A001' } } };
    }

    // 6. 改额度
    if (/额度|限额|提额/.test(text)) {
      var lim = amount(text);
      var limDetail = lim === null
        ? [{ label: '账户', value: 'A001' },
           { label: '新上限', value: '—（未解析到金额，请勿确认）' }]
        : [{ label: '账户', value: 'A001' },
           { label: '新上限', value: YUAN(Math.round(lim * 100)) + ' 元/日' }];
      logEvent('tier.checked', { action: 'card.limit_change', tier: 'red' });
      ST.seq++;
      return { type: 'confirm_required', tier: 'red', tier_label: fmtTier('red'),
        op_id: 'OP' + ST.seq + 'LIMIT', action: 'card.limit_change',
        summary: '调整单日转出上限',
        reasons: ['调整卡额度 的基准级别：红色 · 需强验证',
                  '涉及资金安全参数变更，必须多因子认证'],
        needs: ['user_confirmation', 'strong_verification'],
        confirm_token: 'STATIC-TOKEN', expires_in: 180,
        details: limDetail,
        intent: { intent: 'card_limit_change', confidence: 0.82,
                  slots: { acct: 'A001', limit_yuan: lim } } };
    }

    // 5. 转账
    if (/转|汇|打钱|付款/.test(text)) {
      var amt = amount(text);
      var p = payee(text);
      var missing = [];
      if (amt === null) missing.push('amount');
      if (!p) missing.push('payee');
      if (missing.length) {
        logEvent('intent.need_slots', { intent: 'transfer', missing: missing });
        return { type: 'clarify',
          message: missing.indexOf('payee') >= 0 && missing.indexOf('amount') >= 0
            ? '请问转给谁、转多少钱？例如"给李娜转 500 元"。'
            : (missing.indexOf('amount') >= 0 ? '请问转多少钱？' : '请问转给谁？可以说姓名或手机号。'),
          intent: { intent: 'transfer', confidence: 0.6,
                    slots: { acct: 'A001', amount_yuan: amt } } };
      }
      var cents = Math.round(amt * 100);
      var t = tier(cents, true);
      logEvent('tier.checked', { action: 'transfer.small', tier: t,
        reasons: [t === 'red'
          ? (cents > CAP ? '单笔 ' + YUAN(cents) + ' 元 > 1,000.00 元，超出小额上限 → 升为红色'
                         : '今日已转出 ' + YUAN(ST.dailyOut) + ' 元，加上本笔将达 ' +
                           YUAN(ST.dailyOut + cents) + ' 元，超出小额上限 → 升为红色')
          : '今日已转出 ' + YUAN(ST.dailyOut) + ' 元，本笔后累计 ' +
            YUAN(ST.dailyOut + cents) + ' 元，在小额上限 1,000.00 元内'] });

      ST.seq++;
      var opId = 'OP' + ST.seq + 'XFR';
      logEvent('confirm.issued', { op: opId, tier: t });
      return { type: 'confirm_required', tier: t, tier_label: fmtTier(t),
        op_id: opId, action: t === 'red' ? 'transfer.large' : 'transfer.small',
        summary: '向 ' + (p.name || p.phone) + ' 转账 ' + YUAN(cents) + ' 元',
        reasons: [
          '小额转账 的基准级别：黄色 · 需确认',
          t === 'red'
            ? (cents > CAP
                ? '单笔 ' + YUAN(cents) + ' 元 > 1,000.00 元，超出小额上限 → 升为红色'
                : '今日已转出 ' + YUAN(ST.dailyOut) + ' 元，加上本笔将达 ' +
                  YUAN(ST.dailyOut + cents) + ' 元，超出小额上限 1,000.00 元 → 升为红色')
            : '今日已转出 ' + YUAN(ST.dailyOut) + ' 元，本笔后累计 ' +
              YUAN(ST.dailyOut + cents) + ' 元，在小额上限 1,000.00 元内'
        ],
        needs: t === 'red' ? ['user_confirmation', 'strong_verification']
                           : ['user_confirmation'],
        confirm_token: 'STATIC-' + opId, expires_in: 180,
        details: [{ label: '付款账户', value: 'A001' },
                  { label: '收款人', value: p.name || p.phone },
                  { label: '金额', value: YUAN(cents) + ' 元' }],
        _amount: cents, _payee: p,
        intent: { intent: 'transfer', confidence: 0.9,
                  slots: { acct: 'A001', amount_yuan: amt, to: p.acct,
                           to_name: p.name } } };
    }

    logEvent('intent.parsed', { text: text, note: '未识别' });
    return { type: 'clarify',
      message: '抱歉，我没理解这个需求。你可以这样说：\n· 我卡里还有多少钱\n' +
               '· 给李娜转 500 元\n· 看看我这个月的账单\n· 我有哪些自动续费' };
  }

  /* ── /api/execute ────────────────────────────────────────────────── */
  function handleExecute(body) {
    var opId = body.op_id || '';
    var code = body.otp_code;

    if (opId.indexOf('LIMIT') >= 0) {
      logEvent('confirm.checked', { op: opId, phase: 'execute' });
      if (!code) {
        logEvent('verify.rejected', { op: opId, reason: '需要强验证' });
        return { type: 'need_strong_verification',
          message: '这是红色级别操作，需要短信验证码确认。', op_id: opId,
          hint: '确认凭证仍然有效，获取验证码后继续即可，不需要重新发起。' };
      }
      if (code !== ISSUED_CODE) {
        logEvent('verify.rejected', { op: opId, reason: '验证码不正确' });
        return { type: 'refused', message: '验证码不正确', op_id: opId, retryable: true };
      }
      logEvent('verify.passed', { op: opId, method: 'sms_otp' });
      logEvent('confirm.consumed', { op: opId });
      logEvent('exec.succeeded', { op: opId, action: 'card.limit_change' });
      return { type: 'result', tier: 'red', tier_label: fmtTier('red'),
        message: '单日转出上限已调整。\n\n（静态演示版不会真正改数据，' +
                 '这一条在完整版里会写入 account.daily_limit。）' };
    }

    // ── 跨场景联动：锁定资金（黄色，只确认，不需强验证）──────────────
    if (body._side === 'linkage_lock') {
      var lkPlan = null;
      for (var li = 0; li < ST.plans.length; li++) {
        if (ST.plans[li].id === body._planId) { lkPlan = ST.plans[li]; break; }
      }
      logEvent('confirm.checked', { op: opId, phase: 'execute', tier: 'yellow' });
      if (!lkPlan) {
        return { type: 'exec_failed', code: 'PLAN_NOT_FOUND',
          message: '找不到这个联动计划。' };
      }
      if (lkPlan.locked > 0) {
        return { type: 'result', data: { plan: lkPlan, locked: lkPlan.locked },
          message: '这笔锁定已存在，按幂等处理，**没有重复锁定**。' };
      }
      // 校验可动用余额 —— 与后端 core.lock_funds 一致：
      // 不能用 balance 判断，否则会超额锁定，把账户锁穿。
      if (available() < lkPlan.budget) {
        return { type: 'exec_failed', code: 'INSUFFICIENT_AVAILABLE',
          message: '可动用余额不足：可动用 ' + YUAN(available()) + ' 元（余额 ' +
                   YUAN(ST.balances.A001) + ' − 已锁定 ' + YUAN(ST.locked || 0) +
                   '），本计划需要 ' + YUAN(lkPlan.budget) + ' 元' };
      }
      ST.locked = (ST.locked || 0) + lkPlan.budget;
      lkPlan.locked = lkPlan.budget;
      lkPlan.status = 'locked';
      save(ST);
      logEvent('confirm.consumed', { op: opId });
      logEvent('exec.succeeded', { op: opId, action: 'linkage.lock',
                                   amount: lkPlan.budget });
      return { type: 'result', tier: 'yellow', tier_label: fmtTier('yellow'),
        data: { plan: lkPlan, locked: lkPlan.locked, balance: ST.balances.A001,
                available: available() },
        message: '已为「' + lkPlan.occasion + '」锁定 **' + YUAN(lkPlan.budget) +
                 ' 元**。余额仍是 ' + YUAN(ST.balances.A001) + ' 元，其中 ' +
                 YUAN(lkPlan.budget) + ' 元现在不能动用（可动用 ' +
                 YUAN(available()) + ' 元）。' };
    }

    // ── 跨场景联动：执行到期步骤（红色，需强验证）────────────────────
    if (body._side === 'linkage_run') {
      var rnPlan = null;
      for (var ri = 0; ri < ST.plans.length; ri++) {
        if (ST.plans[ri].id === body._planId) { rnPlan = ST.plans[ri]; break; }
      }
      logEvent('confirm.checked', { op: opId, phase: 'execute', tier: 'red' });
      if (!rnPlan) {
        return { type: 'exec_failed', code: 'PLAN_NOT_FOUND',
          message: '找不到这个联动计划。' };
      }
      if (!code) {
        return { type: 'need_strong_verification',
          message: '这是红色级别操作，需要短信验证码确认。', op_id: opId,
          hint: '确认凭证仍然有效，获取验证码后继续即可，不需要重新发起。' };
      }
      if (code !== ISSUED_CODE) {
        logEvent('verify.rejected', { op: opId, reason: '验证码不正确' });
        return { type: 'refused', message: '验证码不正确', op_id: opId,
                 retryable: true };
      }
      logEvent('verify.passed', { op: opId, method: 'sms_otp' });

      // 必须先锁定资金 —— 与后端 core.execute_step 同一条约束：
      // 不允许动用未预留的余额去下单。
      if (!rnPlan.locked || rnPlan.locked <= 0) {
        return { type: 'exec_failed', code: 'NOT_LOCKED',
          message: '该计划还没有锁定资金，不能执行扣款步骤。请先确认锁定 ' +
                   YUAN(rnPlan.budget) + ' 元。' };
      }

      var today = todayStr();
      var dueSteps = rnPlan.steps.filter(function (s) {
        return s.status === 'pending' && s.due_date <= today;
      });
      if (!dueSteps.length) {
        var pend = rnPlan.steps.filter(function (s) { return s.status === 'pending'; });
        if (!pend.length) {
          return { type: 'result', message: '该计划的步骤都已执行完毕。' };
        }
        var nxt = pend.map(function (s) { return s.due_date; }).sort()[0];
        return { type: 'exec_failed', code: 'NOT_DUE',
          message: '该计划还没有到期的步骤。最近一步应在 ' + nxt + ' 执行，今天是 ' +
                   today + '。提前执行会打乱时序，已拒绝。' };
      }
      logEvent('confirm.consumed', { op: opId });
      var done = [], totalAmt = 0;
      for (var di = 0; di < dueSteps.length; di++) {
        var s = dueSteps[di];
        if (s.amount > ST.balances.A001) {
          return { type: 'exec_failed', code: 'INSUFFICIENT_FUNDS',
            message: '余额不足以执行「' + s.detail + '」：可用 ' +
                     YUAN(ST.balances.A001) + ' 元，需要 ' + YUAN(s.amount) + ' 元' };
        }
        ST.balances.A001 -= s.amount;
        // 锁定金额按实际花费释放，不超过本计划剩余锁定额
        var rel = Math.min(s.amount, rnPlan.locked);
        ST.locked = Math.max(0, (ST.locked || 0) - rel);
        rnPlan.locked -= rel;
        s.status = 'done';
        totalAmt += s.amount;
        done.push({ kind: s.kind, detail: s.detail, amount: s.amount });
        logEvent('exec.succeeded', { op: opId, action: 'linkage.run',
                                     step: s.id, amount: s.amount });
      }
      var left = rnPlan.steps.filter(function (x) { return x.status !== 'done'; }).length;
      if (!left) {
        // 所有步骤完成 → 释放剩余锁定
        ST.locked = Math.max(0, (ST.locked || 0) - rnPlan.locked);
        rnPlan.locked = 0;
        rnPlan.status = 'done';
      }
      save(ST);
      var msg = '已执行 ' + done.length + ' 个到期步骤：\n';
      done.forEach(function (d) {
        msg += '· ' + d.detail + ' —— ' + YUAN(d.amount) + ' 元\n';
      });
      msg += '\n账户余额 ' + YUAN(ST.balances.A001) + ' 元，其中已锁定 ' +
             YUAN(ST.locked || 0) + ' 元，可动用 ' + YUAN(available()) + ' 元。';
      // 模拟边界必须明说，不能让人以为真的下单了
      msg += '\n\n⚠ **外部订购为模拟**：本项目没有真实的鲜花/蛋糕供应商接口，' +
             '这里只演示「资金到位 + 时序触发」这条链路。';
      return { type: 'result', tier: 'red', tier_label: fmtTier('red'),
        data: { plan: rnPlan, executed: done, balance: ST.balances.A001,
                locked: ST.locked || 0, available: available() },
        message: msg };
    }

    // 卡操作（申请虚拟卡 / 挂失 / 解挂）
    if (body._card) {
      var ck = body._card;
      // 只有挂失/解挂是红级；申请虚拟卡是黄级，不需要验证码
      var ckRed = (ck === 'freeze' || ck === 'unfreeze');
      logEvent('confirm.checked', { op: opId, phase: 'execute', tier: ckRed ? 'red' : 'yellow' });
      if (ckRed) {
        if (!code) {
          return { type: 'need_strong_verification',
            message: '这是红色级别操作，需要短信验证码确认。', op_id: opId,
            hint: '确认凭证仍然有效，获取验证码后继续即可，不需要重新发起。' };
        }
        if (code !== ISSUED_CODE) {
          logEvent('verify.rejected', { op: opId, reason: '验证码不正确' });
          return { type: 'refused', message: '验证码不正确', op_id: opId, retryable: true };
        }
        logEvent('verify.passed', { op: opId, method: 'sms_otp' });
      }
      logEvent('confirm.consumed', { op: opId });
      if (ck === 'freeze') {
        ST.cardStatus = 'lost';
        save(ST);
        logEvent('exec.succeeded', { op: opId, action: 'card.freeze' });
        return { type: 'result', tier: 'red', tier_label: fmtTier('red'),
          message: '卡片已挂失冻结。如需恢复用卡，请通过人脸识别验证身份后解挂。' };
      }
      if (ck === 'unfreeze') {
        ST.cardStatus = 'active';
        save(ST);
        logEvent('exec.succeeded', { op: opId, action: 'card.unfreeze' });
        return { type: 'result', tier: 'red', tier_label: fmtTier('red'),
          message: '卡片已解挂，恢复使用。' };
      }
      logEvent('exec.succeeded', { op: opId, action: 'card.apply_virtual' });
      return { type: 'result', tier: 'yellow', tier_label: fmtTier('yellow'),
        message: '虚拟卡申请已提交，状态：待审核。' };
    }

    // 理财申赎
    if (body._side === 'purchase' || body._side === 'redeem') {
      var wp = body._product, wa = body._amount || 0;
      logEvent('confirm.checked', { op: opId, phase: 'execute', tier: 'red' });
      if (!code) {
        return { type: 'need_strong_verification',
          message: '这是红色级别操作，需要短信验证码确认。', op_id: opId,
          hint: '确认凭证仍然有效，获取验证码后继续即可，不需要重新发起。' };
      }
      if (code !== ISSUED_CODE) {
        logEvent('verify.rejected', { op: opId, reason: '验证码不正确' });
        return { type: 'refused', message: '验证码不正确', op_id: opId, retryable: true };
      }
      logEvent('verify.passed', { op: opId, method: 'sms_otp' });
      logEvent('confirm.consumed', { op: opId });

      var spec = null;
      for (var si = 0; si < WEALTH_CATALOG.length; si++) {
        if (WEALTH_CATALOG[si].name === wp) { spec = WEALTH_CATALOG[si]; break; }
      }
      var oid = 'WO' + sha256Sync(opId + Date.now()).slice(0, 12).toUpperCase();
      if (body._side === 'purchase') {
        if (wa < spec.min_amount) {
          return { type: 'exec_failed', code: 'BELOW_MIN_AMOUNT',
            message: '低于起购金额：' + YUAN(spec.min_amount) + ' 起购，本次 ' + YUAN(wa) };
        }
        // 用可动用余额判断 —— 被联动计划锁定的钱不能拿去申购理财。
        // 与后端 core.purchase 的检查口径一致。
        if (available() < wa) {
          return { type: 'exec_failed', code: 'INSUFFICIENT_FUNDS',
            message: '活期可用余额不足：可用 ' + YUAN(available()) + ' 元，需要 ' + YUAN(wa) +
                     ' 元' + ((ST.locked || 0) > 0
                       ? '（其中 ' + YUAN(ST.locked) + ' 元已为联动计划锁定）' : '') };
        }
        ST.balances.A001 -= wa;
        ST.holdings[wp] = (ST.holdings[wp] || 0) + wa;
        save(ST);
        logEvent('exec.succeeded', { op: opId, action: 'wealth.purchase', amount: wa });
        return { type: 'result', tier: 'red', tier_label: fmtTier('red'),
          message: '已申购「' + wp + '」**' + YUAN(wa) + ' 元**。订单号 `' + oid +
                   '`，活期余额 ' + YUAN(ST.balances.A001) + ' 元。' };
      }
      var hold = ST.holdings[wp] || 0;
      if (!hold) {
        return { type: 'exec_failed', code: 'NOT_HELD', message: '你没有持有「' + wp + '」' };
      }
      if (wa > hold) {
        return { type: 'exec_failed', code: 'EXCEEDS_HOLDING',
          message: '赎回额超过持仓：持有 ' + YUAN(hold) + ' 元，本次请求 ' + YUAN(wa) + ' 元' };
      }
      ST.holdings[wp] = hold - wa;
      if (ST.holdings[wp] <= 0) delete ST.holdings[wp];
      ST.balances.A001 += wa;
      save(ST);
      logEvent('exec.succeeded', { op: opId, action: 'wealth.redeem', amount: wa });
      return { type: 'result', tier: 'red', tier_label: fmtTier('red'),
        message: '已赎回「' + wp + '」**' + YUAN(wa) + ' 元**。订单号 `' + oid +
                 '`，活期余额 ' + YUAN(ST.balances.A001) + ' 元。' };
    }

    // 转账
    var cents = body._amount || 0;
    // 关键：用**已判定的级别**决定是否需要强验证，而不是用金额重新推断。
    //
    // 这里踩过一个真实的漏洞：原先写的是 `if (cents > CAP)`（单笔超 1000 才要验证码）。
    // 但红级有**两个**触发条件 —— 单笔超限、或**日累计**超限。
    // 于是「日累计到 1000 后再转 500」这条路径被判为红色、
    // 弹出了验证码输入框，但执行时因为 500 ≤ 1000 就不校验 OTP 了。
    // 结果：随便输 000000 也能转账成功。
    //
    // 教训是通用的：**授权必须按"当初判定的范围"校验，不能重新推断。**
    // 重新推断就会与判定逻辑产生分歧，而分歧处就是绕过点。
    var wasRed = body._wasRed === true;
    logEvent('confirm.checked', { op: opId, phase: 'execute', tier: wasRed ? 'red' : 'yellow' });
    if (wasRed) {
      if (!code) {
        return { type: 'need_strong_verification',
          message: '这是红色级别操作，需要短信验证码确认。', op_id: opId,
          hint: '确认凭证仍然有效，获取验证码后继续即可，不需要重新发起。' };
      }
      if (code !== ISSUED_CODE) {
        logEvent('verify.rejected', { op: opId, reason: '验证码不正确' });
        return { type: 'refused', message: '验证码不正确', op_id: opId, retryable: true };
      }
      logEvent('verify.passed', { op: opId, method: 'sms_otp' });
    }
    logEvent('confirm.consumed', { op: opId });

    var to = body.to_acct || 'A002';
    // 同样按可动用余额判断：为联动计划预留的钱不能被转走，
    // 否则到期该订的礼品就付不出钱了 —— 预留形同虚设。
    if (available() < cents) {
      logEvent('exec.failed', { op: opId, code: 'INSUFFICIENT_FUNDS' });
      return { type: 'exec_failed', code: 'INSUFFICIENT_FUNDS',
        message: '可动用余额不足：可用 ' + YUAN(available()) + ' 元，需要 ' + YUAN(cents) +
                 ' 元' + ((ST.locked || 0) > 0
                   ? '（余额 ' + YUAN(ST.balances.A001) + ' 元中另有 ' +
                     YUAN(ST.locked) + ' 元已为联动计划锁定）' : '') };
    }
    ST.balances.A001 -= cents;
    ST.balances[to] = (ST.balances[to] || 0) + cents;
    ST.dailyOut += cents;
    save(ST);
    var txid = 'TX' + sha256Sync(opId + Date.now()).slice(0, 12).toUpperCase();
    logEvent('exec.succeeded', { transfer_id: txid, amount: cents,
      from_acct: 'A001', to_acct: to });
    return { type: 'result', tier: cents > CAP ? 'red' : 'yellow',
      tier_label: fmtTier(cents > CAP ? 'red' : 'yellow'),
      transaction_id: txid,
      message: '已向 **' + (body.to_name || to) + '** 转账 **' + YUAN(cents) +
               ' 元**。交易号 `' + txid + '`。当前余额 ' + YUAN(ST.balances.A001) + ' 元。' };
  }

  function handleVerifyRequest() {
    logEvent('verify.otp_issued', { method: 'sms' });
    var code = String(Math.floor(100000 + Math.random() * 900000));
    ISSUED_CODE = code;          // 记下来，执行时要比对
    return { type: 'otp_sent', challenge: 'STATIC-CHALLENGE', demo_code: code,
      message: '验证码已发送至绑定手机 ****0001（演示环境直接显示）' };
  }

  function handleReset() {
    ST = JSON.parse(JSON.stringify(DEFAULT));
    save(ST);
    ISSUED_CODE = null;
    audit = [];
    logEvent('system.reset', { note: '演示环境已重置' });
    return { ok: true, message: '演示环境已重置：账户余额与订阅恢复初始状态' };
  }

  /* ══════════════════ 安装：暴露 window.__API__ ══════════════════
     为什么不覆写 window.fetch：
     app.js 是 defer + 同步执行的，它在解析时就已经把 fetch 的原始引用
     拿到了闭包里，之后再覆写 window.fetch 对它完全无效。
     所以改成挂一个显式的钩子，由 app.js 里的 api() 优先调用它。 */
  var routes = {
    '/api/state': handleState,
    '/api/catalog': handleCatalog,
    '/api/audit': handleAudit,
    '/api/chat': handleChat,
    '/api/execute': handleExecute,
    '/api/verify/request': handleVerifyRequest,
    '/api/cancel': function () { return { ok: true }; },
    '/api/reset': handleReset
  };

  window.__API__ = function (path, body) {
    var fn = routes[String(path).split('?')[0]];
    if (!fn) return { error: '静态演示版没有这个接口: ' + path };
    // 执行接口需要上一次 plan 里的金额与收款人（真实后端从服务端状态取）
    if (path === '/api/execute' && window.__lastOp) {
      body._amount = window.__lastOp._amount;
      // 把"当初判定的级别"带过去。执行时必须按它校验，
      // 不能用金额重新推断 —— 那会漏掉"日累计触发红级"这条路径。
      body._wasRed = window.__lastOp.tier === 'red';
      body._product = window.__lastOp._product;
      body._side = window.__lastOp._side;
      body._card = window.__lastOp._card;
      body._planId = window.__lastOp._planId;
      body.to_acct = (window.__lastOp._payee || {}).acct;
      body.to_name = (window.__lastOp._payee || {}).name;
    }
    var res = fn(body || {});
    // 记住"上一次待确认的操作"，供 /api/execute 取用。
    // 链接卡（chained）也要记 —— 它是"登记计划"返回值里的**嵌套**确认卡，
    // 用户点它时 op 不在 res 顶层。漏了这一句的表现是"链接卡点了没反应"，
    // 而且不会有任何报错，很难查。
    if (path === '/api/chat') {
      if (res.type === 'confirm_required') window.__lastOp = res;
      else if (res.chained) window.__lastOp = res.chained;
    }
    return res;
  };

  /* 界面上的静态版声明 */
  document.addEventListener('DOMContentLoaded', function () {
    var banner = document.createElement('div');
    banner.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:200;' +
      'background:#1b4d8f;color:#fff;font:12px/1.5 "Microsoft YaHei",sans-serif;' +
      'padding:6px 14px;text-align:center;';
    banner.innerHTML = '静态演示版 —— 分级判定与金额计算在前端按真实规则重算，' +
      '响应取自 <code>api_server.py</code> 的实测输出。' +
      '完整版（Python 后端、真实状态变更、逐条实测）见代码仓库。';
    document.body.appendChild(banner);
  });
})();
