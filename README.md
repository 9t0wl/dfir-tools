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

*First used on HTB Sherlock "Baggage" (shellbags analysis). Writeup: https://9t0wl.github.io/Blue-Team-Portfolio/*
