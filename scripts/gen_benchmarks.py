#!/usr/bin/env python3
"""Emit README benchmark charts as standalone SVGs + PNGs (dark/light).

Two figures: launch metrics (spawn, ready-to-type, warm launch) and
footprint/efficiency (RSS, disk, per-prompt tax, input tokens).
Run: python3 scripts/gen_benchmarks.py   (requires rsvg-convert for PNGs)
"""
import math
import pathlib
import subprocess
import html as H

W = 848
LEFT, BAR_W, ROW_H, BH = 245, 465, 28, 19
FONT = "ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif"


def esc(s):
    return H.escape(str(s), quote=True)


def fmt(v, unit):
    if unit == "ms":
        if v >= 1000:
            return f"{v/1000:.2f} s"
        return f"{v:.1f} ms" if v < 10 else f"{v:.0f} ms"
    if unit == "mb":
        return f"{v:.0f} MB"
    if unit == "tok":
        return f"{v/1000:.1f}k" if v >= 1000 else f"{v}"
    return str(v)


# (title, unit, log, chip_override, rows[(label, value, is_fd, ghost)], note)
LAUNCH = [
    ("Spawn: `--version` / `--help`", "ms", True, None,
     [("freedas", 2.3, True, False), ("agentty", 2.6, False, False),
      ("zot", 13, False, False), ("Claude Code", 14, False, False),
      ("jcode", 17, False, False), ("Codex CLI", 77, False, False),
      ("pi", 682, False, False), ("opencode", 777, False, False),
      ("Aider", 1070, False, False), ("Gemini CLI", 2590, False, False)],
     "Median process spawn. agentty.org same-rig for its seven tools; zot/pi "
     "from graphwiz.ai (--help timing)."),
    ("Interactive: launch \u2192 ready to type", "ms", True, None,
     [("freedas", 14, True, False), ("agentty", 47, False, False),
      ("jcode", 56, False, False), ("Forcefield", 334, False, False),
      ("Codex CLI", 402, False, False), ("Claude Code", 635, False, False),
      ("Aider", 1000, False, False), ("Gemini CLI", 3040, False, False),
      ("opencode", 5190, False, False)],
     "agentty.org ready-to-type medians (median of 10, same machine); freedas "
     "= exec \u2192 first TUI byte; Forcefield = warm-launch p50."),
    ("Warm launch p50 (isolated HOME)", "ms", True, None,
     [("freedas", 14, True, False), ("Codex CLI", 73, False, False),
      ("Grok CLI", 203, False, False), ("Forcefield", 334, False, False),
      ("Claude Code", 1588, False, False),
      ("opencode", 2258, False, False)],
     "Forcefield launch-methodology p50s on one rig; freedas measured the same "
     "way (exec \u2192 first byte)."),
]

FOOTPRINT = [
    ("Idle memory (RSS)", "mb", False, None,
     [("freedas", 15, True, False), ("agentty", 21, False, False),
      ("Aider", 74, False, False), ("jcode", 106, False, False),
      ("Claude Code", 152, False, False), ("Codex CLI", 152, False, False),
      ("Gemini CLI", 441, False, False), ("opencode", 651, False, False)],
     "RSS while waiting for input. agentty.org same-rig medians; freedas on "
     "the release build."),
    ("Disk footprint", "mb", False, None,
     [("freedas", 16, True, False), ("agentty", 23, False, False),
      ("jcode", 163, False, False), ("Gemini CLI", 197, False, False),
      ("Claude Code", 325, False, False), ("opencode", 409, False, False),
      ("Codex CLI", 536, False, False), ("Aider", 653, False, False)],
     "Binary + required runtime. agentty.org values; freedas is one stripped "
     "binary, no bundled runtime."),
    ("Per-prompt harness tax", "ms", True, None,
     [("freedas", 13, True, False), ("freedas (pre-lazy)", 80, False, False),
      ("Claude Code overhead", 1690, False, False),
      ("median model response", 3014, False, True)],
     "Overhead beyond model time per trivial prompt. Claude Code: crewshal "
     "TTFT-study median; freedas: full end-to-end run incl. lazy "
     "snapshot-skip."),
    ("Input tokens per trivial prompt", "tok", False,
     "12.9\u00d7 leaner",
     [("Pi \u00b7 no tools", 466, False, True),
      ("Claude Code --bare", 1265, False, True),
      ("freedas \u00b7 17 tools", 1350, True, False),
      ("Pi \u00b7 default", 1641, False, False),
      ("Claude Code \u00b7 4 tools + short sys", 2072, False, False),
      ("Claude Code \u00b7 4 tools", 3316, False, False),
      ("Claude Code \u00b7 21 tools (default)", 17398, False, False),
      ("Codex CLI", 19551, False, False)],
     "Tokens sent for a trivial request, full toolset unless noted. freedas "
     "measured via FREEDAS_DUMP_REQUEST with an empty HOME (~1.4k tokens incl. "
     "17 tool schemas). Pi/CC rows: orbi.build single-request probes; "
     "ghosted rows are intentionally reduced configs. Codex: crewshal "
     "measured 19,551 for a one-line request."),
]

DARK = dict(bg="#0b0e14", panel="#131722", edge="#232c42", text="#e6edf3",
            mut="#8b93a7", bar="#39415a", bar_edge="#4a5578",
            f1="#22d3ee", f2="#34d399", chip="#0e3a30", chip_t="#5eead4",
            ghost_op="0.4")
LIGHT = dict(bg="#ffffff", panel="#f6f8fa", edge="#d0d7de", text="#1f2328",
             mut="#59636e", bar="#d0d7de", bar_edge="#afb8c1",
             f1="#0891b2", f2="#059669", chip="#d1fae5", chip_t="#047857",
             ghost_op="0.45")


def render_chart(title, unit, log, chip_override, rows, note, C, y0):
    out = []
    y = y0
    out.append(
        f'<text x="28" y="{y+14}" fill="{C["text"]}" font-size="14" '
        f'font-weight="650">{esc(title)}</text>')
    maxv = max(r[1] for r in rows)
    fd = rows[[r[2] for r in rows].index(True)][1]
    if chip_override:
        chip_txt = chip_override
    else:
        runner = min(r[1] for r in rows if not r[2])
        ratio = runner / fd
        chip_txt = (f"{ratio:.0f}\u00d7 faster" if ratio >= 2.5
                    else f"{ratio:.1f}\u00d7 faster")
    out.append(
        f'<text x="{W-28}" y="{y+14}" text-anchor="end" fill="{C["mut"]}" '
        f'font-size="10.5">lower is better{" \u00b7 log" if log else ""}</text>')
    y += 26

    def bw(v):
        if log:
            lo, hi = math.log10(0.5), math.log10(maxv)
            return max(3.0, (math.log10(v) - lo) / (hi - lo) * BAR_W)
        return max(3.0, v / maxv * BAR_W)

    for i, (label, val, is_fd, ghost) in enumerate(rows):
        ry = y + i * ROW_H
        w = bw(val)
        lw = 600 if is_fd else 400
        out.append(
            f'<text x="{LEFT-12}" y="{ry+BH*0.72:.0f}" text-anchor="end" '
            f'fill="{C["f2"] if is_fd else C["text"]}" font-size="12" '
            f'font-weight="{lw}">{esc(label)}</text>')
        if is_fd:
            out.append(
                f'<rect x="{LEFT}" y="{ry}" width="{w:.1f}" height="{BH}" rx="5" '
                f'fill="url(#fdg)"/>')
        else:
            op = f' opacity="{C["ghost_op"]}"' if ghost else ""
            out.append(
                f'<rect x="{LEFT}" y="{ry}" width="{w:.1f}" height="{BH}" rx="5" '
                f'fill="{C["bar"]}" stroke="{C["bar_edge"]}" stroke-width="1"{op}/>')
        out.append(
            f'<text x="{LEFT+w+9:.0f}" y="{ry+BH*0.72:.0f}" '
            f'fill="{C["f2"] if is_fd else C["mut"]}" font-size="11.5" '
            f'font-weight="{lw}">{esc(fmt(val, unit))}</text>')
        if is_fd:
            cx, cy = W - 30 - 66, ry + BH / 2
            out.append(
                f'<rect x="{cx}" y="{cy-10}" width="66" height="20" rx="10" '
                f'fill="{C["chip"]}"/>'
                f'<text x="{cx+33}" y="{cy+4}" text-anchor="middle" '
                f'fill="{C["chip_t"]}" font-size="10.5" font-weight="700">'
                f'{esc(chip_txt)}</text>')
    y += len(rows) * ROW_H + 6
    # wrap note into lines at ~95 chars; all lines render, height tracks them
    words, lines, cur = note.split(), [], ""
    for wd in words:
        if len(cur) + len(wd) + 1 > 95:
            lines.append(cur)
            cur = wd
        else:
            cur = f"{cur} {wd}" if cur else wd
    lines.append(cur)
    for j, ln in enumerate(lines):
        out.append(
            f'<text x="{LEFT}" y="{y+12+j*14}" fill="{C["mut"]}" font-size="10">'
            f'{esc(ln)}</text>')
    return "".join(out), y + 14 + len(lines) * 14 + 14


def figure(C, charts, title, subtitle, path):
    # Render chart chunks first so the svg height is exact, not estimated.
    chunks, seps, y = [], [], 84
    for t, unit, log, chip, rows, note in charts:
        chunk, y = render_chart(t, unit, log, chip, rows, note, C, y)
        chunks.append(chunk)
        seps.append(y + 6)
        y += 10
    total = y + 24
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{total}" '
        f'viewBox="0 0 {W} {total}" font-family="{FONT}" role="img" '
        f'aria-label="{esc(title)}">',
        f'<defs><linearGradient id="fdg" x1="0" y1="0" x2="1" y2="0">'
        f'<stop offset="0%" stop-color="{C["f1"]}"/>'
        f'<stop offset="100%" stop-color="{C["f2"]}"/></linearGradient></defs>',
        f'<rect width="{W}" height="{total}" rx="14" fill="{C["panel"]}" '
        f'stroke="{C["edge"]}" stroke-width="1"/>',
        f'<text x="28" y="38" fill="{C["text"]}" font-size="21" font-weight="700">'
        f'{esc(title)}</text>',
        f'<text x="28" y="60" fill="{C["mut"]}" font-size="12">{esc(subtitle)}</text>',
    ]
    for i, chunk in enumerate(chunks):
        out.append(chunk)
        if i < len(chunks) - 1:
            out.append(
                f'<line x1="28" y1="{seps[i]}" x2="{W-28}" y2="{seps[i]}" '
                f'stroke="{C["edge"]}" stroke-width="1"/>')
    out.append("</svg>")
    open(path, "w").write("".join(out))
    print(f"{path}  {total}px")


DOCS = pathlib.Path(__file__).resolve().parent.parent / "docs"
for suffix, C in (("dark", DARK), ("light", LIGHT)):
    figure(C, LAUNCH,
           "freedas \u2014 launch benchmarks",
           "vs every published same-rig number \u00b7 lower is better",
           str(DOCS / f"benchmarks-launch-{suffix}.svg"))
    figure(C, FOOTPRINT,
           "freedas \u2014 footprint & efficiency benchmarks",
           "vs every published same-rig number \u00b7 lower is better",
           str(DOCS / f"benchmarks-footprint-{suffix}.svg"))

# Rasterize to 2x PNGs for GitHub (camo handles PNGs reliably).
for stem in ("benchmarks-launch", "benchmarks-footprint"):
    for suffix in ("dark", "light"):
        svg_p = DOCS / f"{stem}-{suffix}.svg"
        png_p = DOCS / f"{stem}-{suffix}.png"
        subprocess.run(
            ["rsvg-convert", "-w", "1696", str(svg_p), "-o", str(png_p)],
            check=True)
        print(f"{png_p.name}  {(png_p.stat().st_size // 1024)}KB")
