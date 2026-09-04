#!/usr/bin/env python3
"""
dfirtable — turn delimited DFIR tool output into an interactive HTML report.

Built because reading wide, tree-ordered forensic output in a terminal is a
losing battle. Takes pipe/CSV/TSV output from tools like RegRipper, SBECmd,
MFTECmd, or anything else that emits a table, and renders a single
self-contained HTML file that is sortable, filterable, and mergeable across
multiple sources.

Examples
--------
  # RegRipper shellbags, two users merged into one timeline
  dfirtable steve.txt:steve admin.txt:admin -t "Shellbags Timeline" --open

  # Any Eric Zimmerman CSV
  dfirtable Amcache_UnassociatedFileEntries.csv --sort 2 --open

  # Custom highlighting
  dfirtable evtx.csv --hl "4624=ok" --hl "4625=bad" --hl "psexec=warn"

Notes
-----
The HTML template uses __PLACEHOLDER__ / .replace() rather than %-formatting
or .format(), because embedded CSS/JS collides with both ({} and %).
"""

import argparse
import csv
import html
import io
import os
import sys
import webbrowser
from datetime import datetime

DEFAULT_RULES = [
    (".zip",           "warn"),  # archives
    (".rar",           "warn"),
    (".7z",            "warn"),
    ("temp1_",         "bad"),   # Explorer archive extraction
    ("\\appdata\\",    "bad"),
    ("network places", "info"),  # remote access
    ("\\\\",           "info"),
    ("psexec",         "bad"),
    ("mimikatz",       "bad"),
    ("powershell",     "warn"),
]


def sniff_delimiter(sample, override=None):
    if override:
        return {"pipe": "|", "comma": ",", "tab": "\t"}.get(override, override)
    counts = {d: sample.count(d) for d in ("|", "\t", ",")}
    return max(counts, key=counts.get) if max(counts.values()) else ","


def looks_like_separator(cells):
    """RegRipper prints a ---- | ---- rule under its header."""
    joined = "".join(cells).strip()
    return joined and set(joined) <= set("-= ")


def parse(path, label, delim):
    """Return (header, rows). Header is taken from the first usable line."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    lines = [ln for ln in text.splitlines() if delim in ln]
    if not lines:
        print("  [!] no delimited lines found in %s" % path, file=sys.stderr)
        return None, []

    reader = list(csv.reader(io.StringIO("\n".join(lines)), delimiter=delim))
    reader = [[c.strip() for c in row] for row in reader]
    reader = [r for r in reader if not looks_like_separator(r)]
    if not reader:
        return None, []

    header, data = reader[0], reader[1:]
    width = len(header)
    rows = []
    for r in data:
        r = (r + [""] * width)[:width]
        if any(c for c in r):
            rows.append(r + [label])
    return header, rows


def classify(row, rules):
    blob = " ".join(row).lower()
    for pattern, cls in rules:
        if pattern in blob:
            return cls
    return ""


TEMPLATE = """<!doctype html>
<meta charset="utf-8">
<title>__TITLE__</title>
<style>
:root{--bg:#0b1220;--panel:#0d1524;--head:#111b2e;--line:#1b2a42;
      --ink:#cdd9e5;--dim:#5f7690;--cyan:#35c9ff;--amber:#f5b944;--red:#ff5c6c;--green:#3fdc7a}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--ink);margin:0;padding:1.4rem 1.6rem;
     font:13px/1.45 "JetBrains Mono",Consolas,Menlo,monospace}
h1{font-size:1.05rem;color:var(--cyan);margin:0 0 .25rem;letter-spacing:.04em}
.meta{color:var(--dim);margin-bottom:.9rem;font-size:.78rem}
.bar{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center;margin-bottom:.8rem}
input[type=search]{background:var(--panel);border:1px solid var(--line);color:var(--ink);
  padding:.5rem .7rem;width:min(420px,100%);border-radius:4px;font-family:inherit;font-size:.85rem}
input[type=search]:focus{outline:none;border-color:var(--cyan)}
.btn{background:var(--panel);border:1px solid var(--line);color:var(--dim);
  padding:.42rem .7rem;border-radius:4px;cursor:pointer;font-family:inherit;font-size:.75rem}
.btn:hover{border-color:var(--cyan);color:var(--cyan)}
.cols{display:none;gap:.5rem;flex-wrap:wrap;margin-bottom:.8rem;
  background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:.7rem}
.cols.on{display:flex}
.cols label{color:var(--dim);font-size:.75rem;cursor:pointer;white-space:nowrap}
.cols input{accent-color:var(--cyan);margin-right:.25rem}
.wrap{overflow:auto;max-height:calc(100vh - 190px);border:1px solid var(--line);border-radius:4px}
table{border-collapse:collapse;width:100%}
th{background:var(--head);color:var(--cyan);text-align:left;padding:.5rem .65rem;
   position:sticky;top:0;cursor:pointer;white-space:nowrap;border-bottom:1px solid #25384f;
   font-weight:500;z-index:2}
th:hover{background:#16243c}
th .ar{color:var(--dim);font-size:.7rem;margin-left:.3rem}
td{padding:.38rem .65rem;border-bottom:1px solid #131d2e;vertical-align:top;
   max-width:70ch;overflow-wrap:anywhere}
tr:hover td{background:var(--head)}
tr.warn td.tag{color:var(--amber)}
tr.bad  td.tag{color:var(--red)}
tr.info td.tag{color:var(--cyan)}
tr.ok   td.tag{color:var(--green)}
.legend{color:var(--dim);font-size:.75rem}
.legend b{font-weight:500;margin-right:.9rem}
.hidden{display:none}
#count{color:var(--dim);font-size:.75rem;margin-left:.2rem}
</style>

<h1>__TITLE__</h1>
<div class="meta">__ROWCOUNT__ rows &middot; __SOURCES__ &middot; generated __STAMP__</div>

<div class="bar">
  <input type="search" id="q" placeholder="filter rows...  (regex ok)">
  <button class="btn" id="togglecols">columns</button>
  <button class="btn" id="reset">reset</button>
  <span id="count"></span>
  <span class="legend">
    <b style="color:var(--red)">&#9632; suspicious</b>
    <b style="color:var(--amber)">&#9632; archive</b>
    <b style="color:var(--cyan)">&#9632; remote</b>
  </span>
</div>

<div class="cols" id="cols">__COLTOGGLES__</div>

<div class="wrap">
<table id="t">
<thead><tr>__HEAD__</tr></thead>
<tbody>
__BODY__
</tbody>
</table>
</div>

<script>
var table = document.getElementById('t');
var tbody = table.tBodies[0];
var allRows = [].slice.call(tbody.rows);
var counter = document.getElementById('count');

function update(){
  var shown = allRows.filter(function(r){ return r.style.display !== 'none'; }).length;
  counter.textContent = shown + ' / ' + allRows.length + ' shown';
}

/* ---- filter (plain substring, falls back from regex) ---- */
document.getElementById('q').addEventListener('input', function(){
  var v = this.value.toLowerCase(), rx = null;
  try { rx = new RegExp(v, 'i'); } catch (e) { rx = null; }
  allRows.forEach(function(r){
    var t = r.textContent;
    var hit = rx ? rx.test(t) : t.toLowerCase().indexOf(v) !== -1;
    r.style.display = hit ? '' : 'none';
  });
  update();
});

/* ---- sort, numeric-aware ---- */
[].slice.call(table.tHead.rows[0].cells).forEach(function(th, i){
  th.addEventListener('click', function(){
    var rows = [].slice.call(tbody.rows);
    th.asc = !th.asc;
    var dir = th.asc ? 1 : -1;
    rows.sort(function(a, b){
      var x = a.cells[i].textContent.trim(), y = b.cells[i].textContent.trim();
      if (x === '') return 1;
      if (y === '') return -1;
      var nx = parseFloat(x.replace(/[,%]/g, '')), ny = parseFloat(y.replace(/[,%]/g, ''));
      if (!isNaN(nx) && !isNaN(ny) && /^[\\d.,%-]+$/.test(x) && /^[\\d.,%-]+$/.test(y))
        return dir * (nx - ny);
      return dir * x.localeCompare(y);
    });
    rows.forEach(function(r){ tbody.appendChild(r); });
    [].slice.call(table.tHead.rows[0].cells).forEach(function(o){
      var s = o.querySelector('.ar'); if (s) s.textContent = '';
    });
    var mark = th.querySelector('.ar');
    if (mark) mark.textContent = th.asc ? '\\u25B2' : '\\u25BC';
  });
});

/* ---- column visibility ---- */
document.getElementById('togglecols').addEventListener('click', function(){
  document.getElementById('cols').classList.toggle('on');
});
[].slice.call(document.querySelectorAll('#cols input')).forEach(function(cb){
  cb.addEventListener('change', function(){
    var i = +cb.dataset.col;
    var sel = 'tr > *:nth-child(' + (i + 1) + ')';
    [].slice.call(table.querySelectorAll(sel)).forEach(function(cell){
      cell.classList.toggle('hidden', !cb.checked);
    });
  });
});

document.getElementById('reset').addEventListener('click', function(){
  document.getElementById('q').value = '';
  allRows.forEach(function(r){ r.style.display = ''; });
  update();
});

update();
</script>
"""


def main():
    ap = argparse.ArgumentParser(
        prog="dfirtable",
        description="Render delimited DFIR tool output as an interactive HTML report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="input format:  PATH[:LABEL]   e.g.  steve.txt:steve  admin.txt:admin",
    )
    ap.add_argument("inputs", nargs="+", help="input files, optionally PATH:LABEL")
    ap.add_argument("-o", "--out", default="report.html", help="output HTML (default: report.html)")
    ap.add_argument("-t", "--title", default="DFIR Report", help="report title")
    ap.add_argument("-d", "--delim", help="delimiter: pipe|comma|tab or literal char (default: auto)")
    ap.add_argument("-s", "--sort", type=int, default=0, help="column index to sort by (default: 0)")
    ap.add_argument("--hl", action="append", default=[],
                    help="highlight rule 'substring=class' where class is ok|info|warn|bad (repeatable)")
    ap.add_argument("--no-default-rules", action="store_true", help="disable built-in highlight rules")
    ap.add_argument("--open", action="store_true", help="open the report in a browser when done")
    args = ap.parse_args()

    rules = [] if args.no_default_rules else list(DEFAULT_RULES)
    for spec in args.hl:
        if "=" not in spec:
            ap.error("--hl expects 'substring=class', got %r" % spec)
        pat, cls = spec.rsplit("=", 1)
        rules.insert(0, (pat.lower(), cls.strip()))

    header, rows, sources = None, [], []
    for item in args.inputs:
        path, _, label = item.partition(":")
        label = label or os.path.splitext(os.path.basename(path))[0]
        if not os.path.isfile(path):
            print("  [!] not found: %s" % path, file=sys.stderr)
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            delim = sniff_delimiter(fh.read(8192), args.delim)
        hdr, rws = parse(path, label, delim)
        if hdr is None:
            continue
        if header is None:
            header = hdr + ["Source"]
        rows += rws
        sources.append("%s (%d)" % (label, len(rws)))

    if not rows:
        sys.exit("no rows parsed — check --delim, or that the files contain a delimited table")

    idx = min(args.sort, len(header) - 1)
    rows.sort(key=lambda r: (r[idx] == "", r[idx]))

    ncols = len(header)
    head = "".join(
        "<th>" + html.escape(c) + "<span class='ar'></span></th>" for c in header)
    toggles = "".join(
        "<label><input type=checkbox checked data-col=%d>%s</label>" % (i, html.escape(c))
        for i, c in enumerate(header))

    body_parts = []
    for r in rows:
        r = (r + [""] * ncols)[:ncols]
        cls = classify(r, rules)
        cells = "".join(
            "<td class='tag'>" + html.escape(c) + "</td>" for c in r)
        body_parts.append("<tr class='" + cls + "'>" + cells + "</tr>")

    out = (TEMPLATE
           .replace("__TITLE__", html.escape(args.title))
           .replace("__ROWCOUNT__", str(len(rows)))
           .replace("__SOURCES__", html.escape(", ".join(sources)))
           .replace("__STAMP__", datetime.now().strftime("%Y-%m-%d %H:%M"))
           .replace("__COLTOGGLES__", toggles)
           .replace("__HEAD__", head)
           .replace("__BODY__", "\n".join(body_parts)))

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(out)

    print("[+] %d rows -> %s" % (len(rows), args.out))
    if args.open:
        webbrowser.open("file://" + os.path.abspath(args.out))


if __name__ == "__main__":
    main()
