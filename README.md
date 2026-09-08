# dfir-tools

Small utilities built while working DFIR cases — the kind of thing you write at 2am because the output format is fighting you.

---

## `dfirtable.py`

Turns delimited DFIR tool output into a **single self-contained HTML report** that's sortable, filterable, and mergeable across multiple sources.

### Why

Most forensic tools emit wide, flat, pipe- or CSV-delimited tables. In a terminal that means `less -S`, horizontal scrolling, and wrapped columns that destroy the alignment you need to read timestamps against paths.

Worse, some output is ordered *structurally* rather than *chronologically* — RegRipper's shellbags plugin walks the `BagMRU` tree, so entries appear in registry-key order, not the order the user actually did things. Incident work is fundamentally chronological, so the first thing you want is a time-sorted view.

This renders it as a real table you can sort by any column, filter live, and merge across users or hosts with a `Source` column to keep track of provenance.

### Install

```bash
git clone https://github.com/9t0wl/dfir-tools.git ~/tools/dfir-tools
chmod +x ~/tools/dfir-tools/dfirtable.py
mkdir -p ~/.local/bin
ln -sf ~/tools/dfir-tools/dfirtable.py ~/.local/bin/dfirtable
# ensure ~/.local/bin is on PATH, then:
dfirtable --help
```

Python 3, standard library only. No dependencies.

### Usage

```
dfirtable INPUT[:LABEL] [INPUT[:LABEL] ...] [options]

  -o, --out FILE        output HTML (default: report.html)
  -t, --title TEXT      report title
  -d, --delim D         pipe | comma | tab | literal char   (default: auto-detect)
  -s, --sort N          column index to sort by             (default: 0)
      --hl 'STR=CLASS'  highlight rule; CLASS = ok|info|warn|bad  (repeatable)
      --no-default-rules
      --open            open in browser when done
```

### Examples

**RegRipper shellbags, two users merged into one timeline:**

```bash
regripper -r "C/Users/steve/AppData/Local/Microsoft/Windows/UsrClass.dat" -p shellbags > steve.txt
regripper -r "C/Users/admin/AppData/Local/Microsoft/Windows/UsrClass.dat" -p shellbags > admin.txt

dfirtable steve.txt:steve admin.txt:admin -t "Shellbags Timeline" --open
```

**Any Eric Zimmerman CSV** (SBECmd, MFTECmd, AmcacheParser, AppCompatCacheParser):

```bash
dfirtable Amcache_UnassociatedFileEntries.csv --sort 2 --open
```

**Custom highlighting for a logon-event review:**

```bash
dfirtable security.csv --hl "4625=bad" --hl "4624=ok" --hl "psexec=bad" --open
```

### Features

- **Auto-detects** pipe / CSV / TSV; handles quoted CSV fields properly
- **Merges multiple inputs** with a `Source` column, so two users or two hosts become one timeline
- **Click any header to sort** — numeric-aware, so sizes and MFT refs sort correctly rather than lexically
- **Live filter** with regex support, showing a `n / total` match count
- **Column show/hide** toggles — the fix for tables too wide to read
- **Row highlighting** for common DFIR indicators (archives, `Temp1_` Explorer extractions, UNC paths, known tool names), overridable with `--hl`
- **Self-contained output** — one HTML file, no CDN, no JS dependencies, safe to hand to someone else or attach to a report

### Built-in highlight rules

| Pattern | Class | Why it matters |
|---|---|---|
| `.zip` `.rar` `.7z` | warn | staging / collection archives |
| `temp1_` | bad | Explorer extracted an archive — proves it was *opened*, not just downloaded |
| `\appdata\` | bad | common staging and execution location |
| `\\` , `network places` | info | remote/UNC access |
| `psexec`, `mimikatz` | bad | known tooling |
| `powershell` | warn | worth a second look |

### Notes

The HTML template uses `__PLACEHOLDER__` + `str.replace()` rather than `%`-formatting or `.format()` — embedded CSS and JS collide with both (`%}` reads as a format specifier, `{}` as a replacement field). Learned that the hard way.

---

## `vol-triage.html`

A single-file, no-build browser tool for reading **Volatility3 CSV output**. Same problem `dfirtable.py` solves — wide delimited tool output that fights the terminal — but as a live page instead of a generated report, since a memory-dump investigation usually means loading several plugin outputs side by side and pivoting between them by PID as you go, not generating one static file per question.

### Why not just `dfirtable.py` for this too?

`dfirtable.py` is still the right tool for a one-shot merged timeline (shellbags across users, MFT + AmCache correlation). `vol-triage.html` is for the interactive, in-progress phase of a memory investigation: multiple plugin outputs open at once, click a PID in `netscan` and jump straight to its row in `pstree`, toggle off `svchost`/browser noise without re-running a command. Reach for whichever shape fits the moment — they're not mutually exclusive.

### Install

No build step. Open the file directly in a browser, or serve it locally:

```bash
git clone https://github.com/9t0wl/dfir-tools.git ~/tools/dfir-tools
xdg-open ~/tools/dfir-tools/vol-triage.html   # or just double-click it
```

Pure HTML/CSS/JS, no dependencies, nothing loaded into it leaves the browser — safe to point at a live case.

### Usage

Export whatever plugins you need as CSV, then load each file from the page's **+ Add data** button (file picker or paste):

```bash
vol -f memdump.raw windows.info                    # confirm the profile parses first
vol -f memdump.raw -r csv windows.pstree   > pstree.csv
vol -f memdump.raw -r csv windows.cmdline  > cmdline.csv
vol -f memdump.raw -r csv windows.netscan  > netscan.csv
```

Any other plugin works the same way (`windows.malfind`, `windows.filescan`, `windows.registry.printkey`, …) — export with `-r csv`, load it as another tab.

### Features

- **Auto-detects table shape** from the CSV header — a `PID` + `ImageFileName`/`Args` column set gets treated as a process table (noise-hide toggle, PID buttons); `ForeignAddr` + `State` gets treated as a network table (external-only toggle, repeat-IP beacon detection)
- **Click any PID to jump** to its row in the process tab, from anywhere else it appears (network, another plugin's output)
- **Auto-flags rows** — a small keyword/IP heuristic marks living-off-the-land binaries (`powershell.exe`, `cmd.exe`, `rundll32.exe`, …) for review and known-bad indicators (encoded PowerShell, `Public`/`Secret`/`Temp` paths) as critical; a repeated `ForeignAddr` across multiple non-listening sockets gets flagged as a possible beacon
- **Sort, filter, multi-tab** — every column is click-sortable, every tab has its own live text filter, tabs are closable so you can drop a plugin's output once you're done with it

### Notes

Built the same way `dfirtable.py` was — real case output first, generic tool second. Column detection is header-name based (case-insensitive `PID`, `ForeignAddr`, `State`, `ImageFileName`/`Process`), so it should hold up across most `windows.*` plugins without edits; a CSV that matches neither shape still loads as a plain sortable/filterable table with keyword flagging.

---

## `strings2csv.py`

Wraps `strings` (both ASCII and UTF-16LE passes) into a CSV so its output can be loaded into `vol-triage.html` like any other export, instead of living in scrollback.

### Why

Some vol3 plugins hard-code which Windows versions they know how to parse. `windows.consoles` / `windows.cmdscan` (console screen/input buffer recovery — the plugins that would normally catch a pasted command) raise `NotImplementedError` on anything they don't recognize, Windows 7 (NT 6.1 / build 7601) included. The fallback is the same data the plugin would have parsed, recovered by hand: dump the owning process (`conhost.exe` holds the console buffer, not the shell itself) and grep its memory in both encodings, since Windows stores most of this text as UTF-16LE and a plain ASCII-only pass silently misses it.

### Usage

```bash
vol -f memdump.raw windows.memmap --dump --pid <conhost-pid>
python3 strings2csv.py pid.<pid>.dmp --pid <pid> > out.csv

# or pre-filter to the interesting stuff, same as grep -iE by hand
python3 strings2csv.py pid.<pid>.dmp --pid <pid> \
  --pattern 'iex|invoke-expression|frombase64|alias|-enc' > out.csv
```

Columns: `PID, Encoding, Offset, String` — `Encoding` is `ASCII` or `UTF16LE` so you can tell which pass a hit came from. Load the CSV into `vol-triage.html` via **+ Add data**; it has no `ImageFileName`/`ForeignAddr` columns so it loads as a plain sortable/filterable table with keyword flagging, and its `PID` column still cross-references into any process tab you've already loaded.

Python 3, standard library only, shells out to `strings` (binutils — already on Kali).

### License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship it in your own toolkit.

---

*`dfirtable.py` first used on HTB Sherlock "Baggage" (shellbags analysis). `vol-triage.html` and `strings2csv.py` first used on HTB Sherlock "Recollection" (Windows 7 memory dump). Writeups: https://9t0wl.github.io/Blue-Team-Portfolio/*
