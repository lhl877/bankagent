#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
md2pdf.py —— 把项目文档转成可提交的 PDF

为什么自己写转换器
==================
这台机器上没有任何 Markdown 库，也没有 pandoc/wkhtmltopdf/LibreOffice。
但有两样东西可用：
  · 标准库 —— 足够解析本项目的 Markdown 子集
  · Edge 的 printToPDF —— 由浏览器排版并嵌入系统中文字体

所以路径是：Markdown → HTML（本脚本）→ PDF（tools/cdp.py 的 pdf 动作）。

只支持本项目实际用到的语法（不做通用解析器）：
  标题 / 段落 / 表格（GFM 管道表）/ 围栏代码块 / 有序与无序列表 /
  引用块 / 水平线 / 行内：粗体、行内代码、链接

刻意不支持的部分及原因：
  · 图片 —— 文档里没有插图（架构图是 ASCII，直接当等宽代码块渲染）
  · HTML 内联 —— 避免把文档里的 HTML 片段当结构执行
  · 脚注/数学 —— 用不到
"""

import html
import os
import re
import sys

FENCE = '`' * 3

# ── 行内元素 ──────────────────────────────────────────────────────────
# 顺序关键：先抽出行内代码并换成占位符，避免代码里的 * _ 被当成强调标记。
_CODE_RE = re.compile(r'`([^`]+)`')


def inline(text):
    """处理行内标记。先保护代码，再处理强调，最后还原。"""
    stash = []

    def stash_code(m):
        stash.append(m.group(1))
        return '\x00%d\x00' % (len(stash) - 1)

    text = _CODE_RE.sub(stash_code, text)
    text = html.escape(text, quote=False)
    # 粗体
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    # 斜体（避免误吃粗体残留）
    text = re.sub(r'(?<!\*)\*([^*\n]+?)\*(?!\*)', r'<em>\1</em>', text)
    # 链接 [文本](地址)
    text = re.sub(r'\[([^\]]+)\]\(([^)\s]+)\)',
                  r'<a href="\2">\1</a>', text)

    def restore(m):
        return '<code>%s</code>' % html.escape(stash[int(m.group(1))], quote=False)

    return re.sub(r'\x00(\d+)\x00', restore, text)


def slug(text):
    """标题 → 锚点 id。中文直接保留（HTML5 允许），只去掉空格和标点。"""
    s = re.sub(r'[^\w\u4e00-\u9fff-]+', '-', text.strip())
    return s.strip('-').lower() or 'sec'


# ── 块级解析 ──────────────────────────────────────────────────────────
def convert(md):
    lines = md.split('\n')
    out = []
    toc = []
    i = 0
    n = len(lines)

    def close_list(stack):
        while stack:
            out.append('</%s>' % stack.pop())

    list_stack = []

    while i < n:
        line = lines[i]

        # 围栏代码块
        if line.lstrip().startswith(FENCE):
            close_list(list_stack)
            lang = line.lstrip()[len(FENCE):].strip()
            body = []
            i += 1
            while i < n and not lines[i].lstrip().startswith(FENCE):
                body.append(lines[i])
                i += 1
            i += 1
            text = '\n'.join(body)
            # 含盒线/箭头的块按「图形」处理：用专门的字体栈，
            # 让盒线与 ASCII 同为半宽、中文为全宽（理由见 CSS 里 .art 的注释）
            art = bool(re.search(r'[\u2500-\u257f\u25b2\u25bc]', text))
            cls = ' class="art"' if art else (
                ' class="lang-%s"' % html.escape(lang) if lang else '')
            out.append('<pre%s><code>%s</code></pre>'
                       % (cls, html.escape(text, quote=False)))
            continue

        # 表格：当前行是 |...| 且下一行是分隔行
        if (line.strip().startswith('|') and i + 1 < n
                and re.match(r'^\s*\|[\s:|-]+\|\s*$', lines[i + 1])):
            close_list(list_stack)
            header = split_row(line)
            i += 2
            rows = []
            while i < n and lines[i].strip().startswith('|'):
                rows.append(split_row(lines[i]))
                i += 1
            out.append('<table><thead><tr>')
            out.extend('<th>%s</th>' % inline(c) for c in header)
            out.append('</tr></thead><tbody>')
            for r in rows:
                out.append('<tr>')
                out.extend('<td>%s</td>' % inline(c) for c in r)
                out.append('</tr>')
            out.append('</tbody></table>')
            continue

        # 标题
        m = re.match(r'^(#{1,6})\s+(.*)$', line)
        if m:
            close_list(list_stack)
            lvl = len(m.group(1))
            text = m.group(2).strip()
            if lvl == 1:
                out.append('<h1>%s</h1>' % inline(text))
            else:
                sid = slug(text)
                if lvl == 2:
                    toc.append((2, text, sid))
                elif lvl == 3:
                    toc.append((3, text, sid))
                out.append('<h%d id="%s">%s</h%d>'
                           % (lvl, sid, inline(text), lvl))
            i += 1
            continue

        # 水平线
        if re.match(r'^\s*(-{3,}|\*{3,}|_{3,})\s*$', line):
            close_list(list_stack)
            out.append('<hr>')
            i += 1
            continue

        # 引用块
        if line.lstrip().startswith('>'):
            close_list(list_stack)
            quote = []
            while i < n and (lines[i].lstrip().startswith('>') or
                             (quote and lines[i].strip() == '')):
                quote.append(re.sub(r'^\s*>\s?', '', lines[i]))
                i += 1
            out.append('<blockquote>%s</blockquote>'
                       % '<br>'.join(inline(q) for q in quote if q.strip()))
            continue

        # 列表
        m = re.match(r'^(\s*)([-*+]|\d+\.)\s+(.*)$', line)
        if m:
            indent, marker, text = len(m.group(1)), m.group(2), m.group(3)
            kind = 'ul' if marker in ('-', '*', '+') else 'ol'
            if list_stack and list_stack[-1] != kind:
                close_list(list_stack)
            if not list_stack:
                out.append('<%s>' % kind)
                list_stack.append(kind)
            out.append('<li>%s</li>' % inline(text))
            i += 1
            continue

        # 空行
        if not line.strip():
            close_list(list_stack)
            i += 1
            continue

        # 段落（连续非空行合并）
        close_list(list_stack)
        para = [line]
        i += 1
        while (i < n and lines[i].strip()
               and not re.match(r'^(#{1,6}\s|\s*[-*+]\s|\s*\d+\.\s|\s*>|\s*' + FENCE + ')', lines[i])
               and not lines[i].strip().startswith('|')
               and not re.match(r'^\s*(-{3,}|\*{3,}|_{3,})\s*$', lines[i])):
            para.append(lines[i])
            i += 1
        out.append('<p>%s</p>' % inline(' '.join(x.strip() for x in para)))

    close_list(list_stack)
    return '\n'.join(out), toc


# ── 自动适配字号 ──────────────────────────────────────────────────────
# ASCII 架构图必须在等宽字体下渲染才对齐，而等宽 CJK 的字宽是 ASCII 的 2 倍
# （这是固定关系，不能像比例字体那样"挤一挤"）。于是同一份图在不同字号下
# 要么超出页宽、要么小到看不清。
#
# 解决办法是在页面上跑一段脚本，逐块量出自然宽度，
# 再按"最大可容纳字号"给每块单独设 inline font-size。
# 这样宽的图自动小一点、窄的代码块保持正常字号，比全局统一字号更合理。
FIT_SCRIPT = '''
(function () {
  var MAX = 666;          // A4 正文可用宽度（px @96dpi，与 @page 边距对应）
  var BASE = 7.4;         // CSS 里的基准字号（pt）
  var pres = [].slice.call(document.querySelectorAll('pre'));
  var report = { total: pres.length, scaled: 0, stillOver: 0, minPt: 99 };
  pres.forEach(function (p) {
    var code = p.querySelector('code');
    if (!code) return;
    code.style.fontSize = BASE + 'pt';
    var w = code.scrollWidth;
    if (w <= MAX) return;
    // 按宽度比例缩字号，留 1% 余量避免亚像素误差
    var pt = Math.max(4.2, BASE * (MAX / w) * 0.99);
    code.style.fontSize = pt.toFixed(2) + 'pt';
    report.scaled++;
    if (pt < report.minPt) report.minPt = Math.round(pt * 100) / 100;
    if (code.scrollWidth > MAX + 1) report.stillOver++;
  });
  return JSON.stringify(report);
})()
'''


def split_row(line):
    """切分表格行，保留 \\| 转义为字面竖线。"""
    s = line.strip().strip('|')
    parts = re.split(r'(?<!\\)\|', s)
    return [p.strip().replace('\\|', '|') for p in parts]


# ── 打印样式 ──────────────────────────────────────────────────────────
CSS = '''
@page { size: A4; margin: 17mm 15mm 16mm 15mm; }
:root {
  --ink:#1c1917; --ink2:#4a4441; --ink3:#7d7671;
  --line:#ddd8d2; --line2:#c3bcb4;
  --accent:#1b4d8f; --soft:#f6f7f9; --code:#f4f5f7;
}
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body {
  margin: 0; color: var(--ink);
  font: 10pt/1.72 "Microsoft YaHei","微软雅黑","PingFang SC",sans-serif;
}
h1 {
  font-size: 20pt; line-height: 1.25; margin: 0 0 4mm;
  padding-bottom: 3mm; border-bottom: 1mm solid var(--accent);
  page-break-after: avoid;
}
h2 {
  font-size: 14pt; margin: 9mm 0 3mm; padding-left: 3mm;
  border-left: 1.2mm solid var(--accent);
  page-break-after: avoid;
}
h3 { font-size: 11.5pt; margin: 6mm 0 2mm; color: var(--ink);
     page-break-after: avoid; }
h4 { font-size: 10.5pt; margin: 4mm 0 1.5mm; color: var(--ink2);
     page-break-after: avoid; }
p { margin: 0 0 2.8mm; }
a { color: var(--accent); text-decoration: none; word-break: break-all; }
strong { font-weight: 700; }
ul, ol { margin: 0 0 3mm; padding-left: 6mm; }
li { margin-bottom: 1.2mm; }

/* 行内代码与代码块：等宽 + 保留空格，ASCII 架构图靠它对齐
   字体栈是这里的关键，踩过坑：
   只写 Consolas + Courier New 时，这两个字体**都没有中文字形**，
   中文会回退到雅黑（比例字体），于是同一行里 ASCII 与中文的宽度不成比例，
   ASCII 架构图的右边框就参差不齐 —— 图还能看，但框线是歪的。
   正确做法是让 **NSimSun（宋体等宽）** 排在中文字符之前：
   它的 CJK 字宽恰好是 ASCII 的 2 倍，正是盒线对齐需要的比例。 */
code {
  font-family: Consolas,"NSimSun","宋体","Cascadia Mono",monospace;
  font-size: 0.9em; background: var(--code);
  border: 0.2mm solid var(--line); border-radius: 0.8mm;
  padding: 0.1mm 0.8mm;
}
pre {
  margin: 3mm 0 4mm; padding: 3mm 3.5mm;
  background: var(--code); border: 0.2mm solid var(--line);
  border-left: 1mm solid var(--line2); border-radius: 0 1.2mm 1.2mm 0;
  overflow: visible; white-space: pre;
  page-break-inside: avoid;
}
pre code {
  background: none; border: 0; padding: 0;
  /* 这里把 NSimSun 放在**最前**，而不是 Consolas 之后。
     原因靠实测确定：用 Range API 量每行像素宽发现，
     Consolas 优先时纯边框行是 5.28px/字符，含中文的行是 5.46px/字符 ——
     因为「─」和中文来自不同字体，比例对不上，ASCII 架构图的右边框就是歪的。
     NSimSun 是等宽字体且 CJK 字宽恰好是 ASCII 的 2 倍，
     这正是盒线对齐需要的关系式，所以让整块都由它排。 */
  font-family: "NSimSun","宋体",Consolas,"Cascadia Mono",monospace;
  font-size: 7.4pt; line-height: 1.5;
  white-space: pre; display: block;
}

/* ── ASCII 图形块（架构图 / 时序图）──────────────────────────────────
   这类块的排版前提是「1 个盒线字符 = 1 个 ASCII 宽度，1 个汉字 = 2 个」。
   实测各字体对这个前提的满足情况：

     NSimSun：ASCII 4.594px，中文 9.172px（=2×），但 **盒线也是 9.172px** ✗
     Consolas：ASCII 4.594px，盒线同为半宽 ✓，但中文回退到别的字体 ✗

   所以没有单一字体同时满足。解法是**分字符走不同字体**：
   把 Consolas 放前面（盒线、ASCII 都从它取半宽），
   NSimSun 紧随其后（缺字形的中文从它取全宽）。
   这样盒线回到 1 格、中文保持 2 格，作者的原始排版就成立了。 */
pre.art code {
  font-family: Consolas,"NSimSun","宋体","Cascadia Mono",monospace;
  font-size: 7.0pt;
  line-height: 1.42;
}

/* 表格 */
table {
  width: 100%; border-collapse: collapse;
  margin: 3mm 0 4.5mm; font-size: 8.6pt;
  page-break-inside: avoid;
}
th, td {
  border: 0.2mm solid var(--line);
  padding: 1.6mm 2mm; text-align: left; vertical-align: top;
  line-height: 1.55;
}
th { background: var(--soft); font-weight: 700; font-size: 8.4pt; }
tbody tr:nth-child(even) td { background: #fbfbfc; }
td code, th code { font-size: 0.88em; }

blockquote {
  margin: 3mm 0; padding: 2.5mm 3.5mm;
  background: var(--soft); border-left: 1mm solid var(--line2);
  color: var(--ink2); font-size: 9.2pt;
  page-break-inside: avoid;
}
hr { border: 0; border-top: 0.2mm solid var(--line); margin: 6mm 0; }

/* 目录 */
.toc {
  background: var(--soft); border: 0.2mm solid var(--line);
  border-radius: 1.5mm; padding: 4mm 5mm; margin: 0 0 8mm;
  page-break-after: always;
}
.toc h2 { border: 0; padding: 0; margin: 0 0 3mm; font-size: 13pt; }
.toc ol { list-style: none; margin: 0; padding: 0; }
.toc li { margin-bottom: 1.4mm; font-size: 9.4pt; }
.toc li.lv3 { padding-left: 6mm; font-size: 8.8pt; color: var(--ink2); }
.toc a { color: var(--ink); }

/* 提交信息块 */
.meta {
  margin: 0 0 7mm; padding: 3mm 4mm;
  border: 0.2mm solid var(--line2); border-radius: 1.5mm;
  font-size: 8.8pt; color: var(--ink2);
  display: grid; grid-template-columns: 26mm 1fr; gap: 1.2mm 3mm;
}
.meta b { color: var(--ink); }
'''

# ── 页面组装 ──────────────────────────────────────────────────────────
META_ROWS = [
    ('作品名称', '安全银行智能体（AI Banking Agent）'),
    ('参赛赛道', '人工智能赛道 · 银行 AI 智能体'),
    ('技术栈', 'Python 3.11（零第三方依赖，全部标准库）+ 原生 HTML/CSS/JS'),
    ('运行方式', 'python api_server.py --port 8090 → http://127.0.0.1:8090/'),
    ('代码规模', '约 4,000 行 Python + 约 1,100 行前端'),
]


def build_html(md_text, title, subtitle):
    body, toc = convert(md_text)
    toc_html = ''
    if toc:
        items = '\n'.join(
            '<li class="lv%d"><a href="#%s">%s</a></li>' % (lv, sid, html.escape(txt))
            for lv, txt, sid in toc)
        toc_html = ('<div class="toc"><h2>目录</h2><ol>%s</ol></div>' % items)

    meta = '\n'.join('<div>%s</div><div><b>%s</b></div>' % (k, html.escape(v))
                     for k, v in META_ROWS)

    return '''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<title>%s</title><style>%s</style></head><body>
<h1>%s</h1>
<p style="color:#7d7671;font-size:9.5pt;margin:-1mm 0 5mm">%s</p>
<div class="meta">%s</div>
%s
%s
<script>%s</script>
</body></html>''' % (html.escape(title), CSS, html.escape(title),
                     html.escape(subtitle), meta, toc_html, body, FIT_SCRIPT)


def main():
    if len(sys.argv) < 3:
        print('用法: python md2pdf.py <输入.md> <输出.html> [标题] [副标题]')
        return 2
    src, dst = sys.argv[1], sys.argv[2]
    title = sys.argv[3] if len(sys.argv) > 3 else os.path.splitext(
        os.path.basename(src))[0]
    subtitle = sys.argv[4] if len(sys.argv) > 4 else ''

    md_text = open(src, encoding='utf-8').read()
    outp = build_html(md_text, title, subtitle)
    with open(dst, 'w', encoding='utf-8') as fh:
        fh.write(outp)

    body, toc = convert(md_text)
    print('  %s → %s' % (src, dst))
    print('    正文 HTML %d 字符 · 目录 %d 条' % (len(body), len(toc)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
