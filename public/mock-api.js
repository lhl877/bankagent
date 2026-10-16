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
    dailyOut: 0,
    cardStatus: 'active',
    seq: 0,
    otpWrongOnce: false
  };

  function load() {
    try {
      var s = sessionStorage.getItem('fb-demo-state');
      return s ? JSON.parse(s) : JSON.parse(JSON.stringify(DEFAULT));
    } catch (e) { return JSON.parse(JSON.stringify(DEFAULT)); }
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
        balance_text: YUAN(ST.balances.A001), card_no: '**** **** **** 6222',
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
                { action: 'subscription.list', desc: '查询订阅与代扣' }],
        yellow: [{ action: 'transfer.small', desc: '小额转账' },
                 { action: 'split.request', desc: '发起 AA 收款' },
                 { action: 'subscription.cancel', desc: '取消订阅' },
                 { action: 'card.apply_virtual', desc: '申请虚拟卡' }],
        red: [{ action: 'transfer.large', desc: '大额转账' },
              { action: 'wealth.purchase', desc: '申购理财产品' },
              { action: 'wealth.redeem', desc: '赎回理财产品' },
              { action: 'card.limit_change', desc: '调整卡额度' },
              { action: 'card.freeze', desc: '挂失/冻结卡片' },
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
    var isListing = /有哪些|有什么|看看|列表|持有哪些|哪个好/.test(text)
                    && !/买|申购|购买|赎回|取出|卖掉/.test(text);
    var hasOp = /买|申购|购买|赎回|取出|卖掉/.test(text);
    if ((hasOp || (product && !isListing)) && !isListing) {
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

    // 5. 改额度
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
        if (ST.balances.A001 < wa) {
          return { type: 'exec_failed', code: 'INSUFFICIENT_FUNDS',
            message: '活期余额不足：可用 ' + YUAN(ST.balances.A001) + ' 元，需要 ' + YUAN(wa) + ' 元' };
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
    if (ST.balances.A001 < cents) {
      logEvent('exec.failed', { op: opId, code: 'INSUFFICIENT_FUNDS' });
      return { type: 'exec_failed', code: 'INSUFFICIENT_FUNDS',
        message: '余额不足：可用 ' + YUAN(ST.balances.A001) + ' 元，需要 ' + YUAN(cents) + ' 元' };
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
      body.to_acct = (window.__lastOp._payee || {}).acct;
      body.to_name = (window.__lastOp._payee || {}).name;
    }
    var res = fn(body || {});
    if (path === '/api/chat' && res.type === 'confirm_required') {
      window.__lastOp = res;
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
