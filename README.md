# lua4-decompiler

LUA 4.x bytecode decompiler, originally built for **CarJacker / AutoThief**.

## Canonical copy lives elsewhere

This repo is now a **mirror / historical archive**. The actively-maintained, canonical decompiler is:

    ../autothief_decomp/tools/lua4-decompile/lua4dec.py

Make changes there and validate with its regression harness
(`tools/lua4-decompile/roundtrip_check.py` against `baseline_roundtrip.json`).
The `lua4dec.py` here is a synced snapshot of that canonical copy (currently `94a02c7`).

**Read [`CAVEATS.md`](CAVEATS.md) before trusting output** — what's fixed, what's still wrong, and the
"round-trip ≠ runnable" rule + metric semantics (DIFFS vs EMPTY_IF vs DROP_LOCAL).

## History / tags

- **`272713c`** (tag `intro-baseline`) — the only revision whose `intro.lua` output runs without hanging the game
  during load. Kept for reference; the canonical copy still has the `JMPT`-into-body negation artifact that affects
  intro's bytecode fidelity (see `CAVEATS.md`).
- **`210fd78`**, **`42c4f6a`** — later iterations in this repo, superseded by the canonical copy.

The `94a02c7` snapshot fixes six bug classes over the older revisions here: reversed multi-return, compound-OR /
empty-if, TAILCALL dropped `return`, dropped `local`, compound-OR with a leading comparison, and merged-else —
all verified by the round-trip harness (DROP_LOCAL 0, EMPTY_IF = 3 genuine stubs). See `CAVEATS.md` for details.
