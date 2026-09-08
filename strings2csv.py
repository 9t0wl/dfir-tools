#!/usr/bin/env python3
"""strings2csv.py — wrap `strings` (ASCII + UTF-16LE) into a CSV vol-triage.html can load.

Built for the case where a vol3 plugin (windows.consoles, windows.cmdscan, ...)
doesn't support the image's OS version and you fall back to dumping a process
and grepping it by hand. This just gives that fallback the same PID / column /
CSV shape as a normal vol3 -r csv export, so it drops into vol-triage.html's
"+ Add data" like anything else instead of living in scrollback.

Usage:
    strings2csv.py DUMP [--pid PID] [--min-len N] [--pattern REGEX] > out.csv

Examples:
    # everything, both encodings
    strings2csv.py pid.3524.dmp --pid 3524 > conhost_3524.csv

    # pre-filtered to the interesting stuff, same as you'd grep by hand
    strings2csv.py pid.3524.dmp --pid 3524 \\
        --pattern 'iex|invoke-expression|frombase64|alias|-enc' \\
        > conhost_3524_filtered.csv

    # whole memory image instead of a per-process dump (slower, wider net)
    strings2csv.py recollection.bin --pattern 'confidential|secret' > hits.csv
"""
import argparse
import csv
import re
import subprocess
import sys


def run_strings(path, encoding_flag, min_len):
    cmd = ["strings", "-t", "x", "-n", str(min_len)]
    if encoding_flag:
        cmd.append(encoding_flag)
    cmd.append(path)
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    for line in result.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        offset, text = parts
        yield offset, text


def main():
    ap = argparse.ArgumentParser(
        description="Convert `strings` output (ASCII + UTF-16LE passes) into a CSV for vol-triage.html",
    )
    ap.add_argument("dump", help="file to run strings against (a process dump, or the raw memory image)")
    ap.add_argument("--pid", default="", help="PID this dump belongs to, recorded as a column (blank if scanning the whole image)")
    ap.add_argument("--min-len", type=int, default=4, help="minimum string length passed to strings -n (default: 4)")
    ap.add_argument("--pattern", default=None, help="case-insensitive regex; only matching strings are written")
    args = ap.parse_args()

    matcher = re.compile(args.pattern, re.IGNORECASE) if args.pattern else None

    writer = csv.writer(sys.stdout)
    writer.writerow(["PID", "Encoding", "Offset", "String"])
    written = 0
    for encoding_flag, label in ((None, "ASCII"), ("-el", "UTF16LE")):
        try:
            for offset, text in run_strings(args.dump, encoding_flag, args.min_len):
                if matcher and not matcher.search(text):
                    continue
                writer.writerow([args.pid, label, "0x" + offset, text])
                written += 1
        except FileNotFoundError:
            print("error: `strings` not found on PATH (binutils)", file=sys.stderr)
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"error: strings failed on {label}: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"wrote {written} rows", file=sys.stderr)


if __name__ == "__main__":
    main()
