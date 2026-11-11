#!/usr/bin/env python3
"""Emit README benchmark charts as standalone SVGs (dark + light variants)."""
import math
import html as H

W = 848
LEFT, BAR_W, ROW_H, BH = 150, 440, 30, 20
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
        return f"{v/1000:.1f}k tokens" if v >= 1000 else f"{v}"
    return str(v)


CHARTS = [
    ("Spawn: freedas --version", "ms", True,
     [("freedas", 2.3, True, False), ("agentty", 2.6, False, False),
      ("Claude Code", 14, False, False), ("jcode", 17, False, False),
      ("Codex CLI", 77, False, False), ("opencode", 777, False, False),
      ("Aider", 1070, False, False), ("Gemini CLI", 2590, False, False)]),
    ("Interactive: launch \u2192 ready to type", "ms", True,
     [("freedas", 14, True, False), ("agentty", 47, False, False),
      ("jcode", 56, False, False), ("Codex CLI", 402, False, False),
      ("Claude Code", 635, False, False), ("Aider", 1000, False, False),
      ("Gemini CLI", 3040, False, False), ("opencode", 5190, False, False)]),
    ("Idle memory", "mb", False,
     [("freedas", 15, True, False), ("agentty", 21, False, False),
      ("Aider", 74, False, False), ("jcode", 106, False, False),
      ("Claude Code", 152, False, False), ("Codex CLI", 152, False, False),
      ("Gemini CLI", 441, False, False), ("opencode", 651, False, False)]),
    ("Disk footprint", "mb", False,
     [("freedas", 16, True, False), ("agentty", 23, False, False),
      ("jcode", 163, False, False), ("Gemini CLI", 197, False, False),
      ("Claude Code", 325, False, False), ("opencode", 409, False, False),
      ("Codex CLI", 536, False, False), ("Aider", 653, False, False)]),
    ("Per-prompt harness tax", "ms", True,
     [("freedas", 13, True, False), ("freedas (pre-lazy)", 80, False, False),
      ("Claude Code overhead", 1690, False, False),
      ("median model response", 3014, False, True)]),
    ("Input tokens per trivial prompt", "tok", False,
     [("freedas", 3700, True, False), ("Codex CLI", 19551, False, False)]),
]

NOTES = [
    "agentty.org same-rig medians \u00b7 log scale",
    "agentty.org ready-to-type medians \u00b7 freedas = exec \u2192 first TUI byte \u00b7 log scale",
    "RSS while waiting for input \u00b7 agentty.org values",
    "Binary + runtime \u00b7 agentty.org values \u00b7 freedas is one stripped binary",
    "Overhead beyond model time \u00b7 Claude Code: crewshal TTFT study \u00b7 log scale",
    "Tokens sent for a one-line request \u00b7 Codex: crewshal measured \u00b7 freedas: ~15KB payload",
]

DARK = dict(bg="#0b0e14", panel="#131722", edge="#232c42", text="#e6edf3",
            mut="#8b93a7", bar="#39415a", bar_edge="#4a5578",
            f1="#22d3ee", f2="#34d399", chip="#0e3a30", chip_t="#5eead4",
            ghost_op="0.45")
LIGHT = dict(bg="#ffffff", panel="#f6f8fa", edge="#d0d7de", text="#1f2328",
             mut="#59636e", bar="#d0d7de", bar_edge="#afb8c1",
             f1="#0891b2", f2="#059669", chip="#d1fae5", chip_t="#047857",
             ghost_op="0.5")


def render_chart(title, unit, log, rows, note, C, y0):
    out = []
    y = y0
    out.append(
        f'<text x="28" y="{y+15}" fill="{C["text"]}" font-size="15" '
        f'font-weight="650">{esc(title)}</text>')
    maxv = max(r[1] for r in rows)
    fd, runner = rows[0][1], min(r[1] for r in rows[1:])
    ratio = runner / fd
    chip_txt = f"{ratio:.0f}\u00d7 faster" if ratio >= 2.5 else f"{ratio:.1f}\u00d7 faster"
    out.append(
        f'<text x="{W-28}" y="{y+15}" text-anchor="end" fill="{C["mut"]}" '
        f'font-size="11">lower is better{" \u00b7 log scale" if log else ""}</text>')
    y += 28

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
            f'fill="{C["f2"] if is_fd else C["text"]}" font-size="12.5" '
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
            f'fill="{C["f2"] if is_fd else C["mut"]}" font-size="12" '
            f'font-weight="{lw}">{esc(fmt(val, unit))}</text>')
        if is_fd:
            cx, cy = W - 28 - 66, ry + BH / 2
            out.append(
                f'<rect x="{cx}" y="{cy-10}" width="66" height="20" rx="10" '
                f'fill="{C["chip"]}"/>'
                f'<text x="{cx+33}" y="{cy+4}" text-anchor="middle" '
                f'fill="{C["chip_t"]}" font-size="11" font-weight="700">'
                f'{esc(chip_txt)}</text>')
    y += len(rows) * ROW_H + 4
    out.append(
        f'<text x="{LEFT}" y="{y+10}" fill="{C["mut"]}" font-size="10.5">'
        f'{esc(note)}</text>')
    return "".join(out), y + 22


def svg(C, path):
    total = 86 + sum(28 + len(c[3]) * ROW_H + 26 + 14 for c in CHARTS)
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{total}" '
        f'viewBox="0 0 {W} {total}" font-family="{FONT}" role="img" '
        f'aria-label="freedas benchmark report">',
        f'<defs><linearGradient id="fdg" x1="0" y1="0" x2="1" y2="0">'
        f'<stop offset="0%" stop-color="{C["f1"]}"/>'
        f'<stop offset="100%" stop-color="{C["f2"]}"/></linearGradient></defs>',
        f'<rect width="{W}" height="{total}" rx="14" fill="{C["panel"]}" '
        f'stroke="{C["edge"]}" stroke-width="1"/>',
        f'<text x="28" y="40" fill="{C["text"]}" font-size="22" font-weight="700">'
        f'freedas <tspan fill="{C["f2"]}">benchmarks</tspan></text>',
        f'<text x="28" y="62" fill="{C["mut"]}" font-size="12.5">Every publicly '
        f'benchmarkable harness category, ranked \u2014 freedas vs published '
        f'same-rig numbers.</text>',
    ]
    y = 82
    for i, (title, unit, log, rows) in enumerate(CHARTS):
        chunk, y = render_chart(title, unit, log, rows, NOTES[i], C, y)
        out.append(chunk)
        if i < len(CHARTS) - 1:
            out.append(
                f'<line x1="28" y1="{y-8}" x2="{W-28}" y2="{y-8}" '
                f'stroke="{C["edge"]}" stroke-width="1"/>')
    open(path, "w").write("".join(out))
    print(f"{path}  {total}px")


import pathlib

DOCS = pathlib.Path(__file__).resolve().parent.parent / "docs"
svg(DARK, str(DOCS / "benchmarks-dark.svg"))
svg(LIGHT, str(DOCS / "benchmarks-light.svg"))
