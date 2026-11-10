# DESIGN.md

Direction supplied by the owner: "Think Codex, Deepseek Harness, Cursor, Devin for design inspiration. NO SLOP."
Audience: developers. Mood and palette: take cues from those products.

## Identity

Freedas web is the window into a local coding agent: a session log you can
steer. It reads like a well-kept terminal workspace, not a marketing dashboard.

## References, inspiration only (R-30)

- Codex: near-monochrome, dense, no chrome around the work.
- DeepSeek Harness: monospace where the data is, restrained status color.
- Cursor: the session rail beside the work.
- Devin: calm surfaces, one accent for the live state.

No product is cloned. The composition is a rail, a transcript, and a composer
built for this screen's job.

## Screen job

Watch one session and steer it: read the transcript, send a prompt, stop a run,
see what it cost. The decision on the screen is "is this run healthy, and what
do I type next?"

## Dials

ENERGY 2 / RHYTHM 2 / MOTION 1

- ENERGY 2: present but quiet; the transcript is the loudest element.
- RHYTHM 2: a fixed rail, a transcript that varies by message kind, and a
  composer that swaps to a running state.
- MOTION 1: hover and focus only, plus one live status dot. Nothing loops.

## Palette (2 core colors + 1 accent)

Dark default, because this is a developer tool (R-21), with a working light
theme.

- `--ink #0f1110`: warm charcoal, not blue-black; neutral dark matches the
  references and warm grey is calmer across a long session.
- `--text #e7e4dd`: warm off-white; contrast without glare.
- `--muted #9aa096`: labels and metadata.
- `--line #2b302c`: hairline separators; structure without boxes.
- `--accent #8fbf8a`: phosphor green, terminal lineage, reserved for the live
  state and the send action so it stays a signal.
- `--warn #d9a441`, `--err #e0785c`: semantic only.

Light theme keeps the same roles on `#f5f3ee`, `#fffefb`, `#23241f`, `#3f7a44`.

## Type

System UI for prose, system monospace for role labels, IDs, and tool data.
The server runs offline, so there is no webfont fetch, and mono where data is
tabular matches the terminal origin.

## Identity motif

A fixed-width role gutter (`you`, `freedas`, `tool`, `system`) in mono, aligned
down the transcript. It is the scan line of the page and the one repeated
gesture.

## Rejected

No gradients, glass, glow, pills, emoji, fake terminal windows, stat-card rows,
charts without a question, invented numbers, or decorative color stripes.

## States

- Empty: says what is missing and offers the one action.
- Loading: names what it is loading.
- Error: names the failure and offers retry.
- Running: a stop control and a labelled live state. Auto-approve is an
  explicit choice, off by default, because it removes prompts.
