# lua4dec.py — caveats & gotchas

Practical notes for anyone using this Lua 4.0.1 bytecode decompiler. Synced from the canonical copy
(`../autothief_decomp/tools/lua4-decompile/lua4dec.py`, `94a02c7`). Read before trusting output.

## The golden rule: round-trip ≠ runnable

A clean `luac4 -p` (parse) and even a byte-identical recompile do **not** guarantee the output behaves like the
original at runtime. A decompiler bug can produce valid Lua that compiles fine but does the wrong thing (a dropped
`local` that silently becomes a global; an inverted condition). **Always eyeball compound conditions and smoke-test
in-game.** The regression harness (`roundtrip_check.py`) is necessary but not sufficient.

### Metric semantics (what's a real bug vs noise)
- **DIFFS** (normalized `luac4 -l` disasm diff, original vs recompiled): a **regression signal only**, NOT pass/fail.
  The decompiler legitimately emits equivalent-but-different jump arrangements for boolean logic, so a non-zero DIFFS
  is normal. Watch that it doesn't *rise* after a change.
- **EMPTY_IF** (`if <cond> then` immediately followed by `end`): a **real bug signal** — the fingerprint of a
  mis-reconstructed compound `or`. Exception: 3 are **genuine empty source stubs** (menu `if GAMEMODE==0/==1 then end`,
  sanjose `if active==1 then end`) — confirmed in bytecode, not bugs.
- **DROP_LOCAL** (recompiled function has fewer locals than the original): a **runtime-breaking bug** — a `local`
  became a global. Pinpoint the variable with `find_dropped_locals.py <file.luab>`. Should be 0.

## Fixed — do NOT re-chase these (all verified by the harness)

1. **Reversed multi-return assignment** — `a, b, c = f()` was emitted as `c, b, a = a, f()` (SETLOCALs arrive in
   reverse target order). Scrambled X/Y and dropped the 3rd result on *every* multi-return coordinate assignment
   (IntersectLine/GetPointOnNetwork/SubVectors/Normalize). The "reversed-temp" output was never faithful.
2. **Compound-OR / empty-if** — an `or` whose operands are >2 instructions apart (e.g. contain a function call,
   often across source lines) was missed and collapsed into inverted/nested ifs with an empty trailing body.
   `_find_next_condition` now scans the operand region with a statement-boundary guard.
3. **TAILCALL dropped `return`** — `return f(args)` was rendered as a bare `f(args)`. The call is now stashed and the
   trailing `OP_RETURN` prints it (reusing its `is_last` / `do..end` wrapping; a naive `return f(args)` would emit a
   double-`return` syntax error because TAILCALL is always followed by RETURN).
4. **Dropped `local`** — a local whose debug `startpc` (scope open) is *after* the instruction that pushed its
   initializer (e.g. a local first read by the `while`/`if` condition that opens its scope) was never declared and
   leaked to a global. Now lazily declared at its true startpc/slot (gated on the per-local `local_init` flag so it
   never double-declares params / multi-return / for-loop vars).
5. **Compound-OR with a leading comparison** — `if (a OP x) or (b and c) then BODY`, where the comparison's
   success-jump targets the body directly, was inverted to `if (a<=x) and (b) then if (c)` (operator flipped, `or`
   dropped). `_find_compound_chain` now scans the condition region `[pcA, BODY)` and classifies each comparison by
   jump target (==BODY → OR/keep, ==END → AND/invert), tightly gated.
6. **Merged-else** — `if C then A else B end` collapsed to `if C then A; B; end` when a *separate* `if` followed on
   the next source line (the else-detector mistook it for an `elseif`). `_find_else_requirement` now requires a
   genuine elseif test to lie before the then-body JMP's target.
7. **Non-ASCII string corruption** — string bytes are read as latin-1 (1 byte = 1 codepoint), but output was written
   as UTF-8, double-encoding every high byte (CP1251 Cyrillic `0xC2` → `0xC3 0x82`), turning the russian/german/
   polish/english text into mojibake that recompiled to the wrong bytes. Output is now written latin-1, byte-faithful.

> **Output encoding:** `.lua` output is **latin-1 / raw bytes**, NOT UTF-8. Lua 4 strings are byte strings and the
> game renders them with its own codepage (e.g. CP1251 for russian.lua). Open the output as latin-1 / the game's
> codepage, not UTF-8 — your editor showing "Âïåðåä" for russian just means it's decoding CP1251 bytes as latin-1.

## Known REMAINING limitations (output is wrong or not byte-exact here)

- **JMPT-into-body negation artifact (intro.lua).** A positive boolean test that jumps *into* the body, and the
  general `if X` → `if not((not X))` rendering, come from the shared `JMPT/JMPF/JMPONT/JMPONF` handler always treating
  JMPT/JMPONT as `not (val)`. The `not((not X))` form is actually **byte-faithful** (recompiles to `NOT;JMPT`) — do
  NOT "simplify" it to `if X` (that emits `JMPF` and *diverges*, shifting downstream jump targets). But a true
  jump-into-body case can add an extra `NOT;JMPF` that is not faithful. intro carries this; its playable version is
  hand-patched. Fixing it properly needs the same OR-success-vs-closing discrimination the comparison path got, with
  careful regression-guarding (the handler is shared with rush/skeleton boolean checks).
- **"Diamond" mixed control flow (menu, rush).** Regions where a body is reachable two ways via mixed
  comparison/boolean jumps (e.g. rush `driver/badguy/copnear`) cannot be expressed as either a nested-if or a flat
  `or` — *neither* form is bytecode-exact. These need manual correction; the decompiler picks one and moves on.
- **Equivalent-but-different jumps.** Even on correct output, expect non-zero DIFFS from legitimately different (but
  semantically identical) jump arrangements. Don't chase DIFFS to zero; chase EMPTY_IF and DROP_LOCAL to zero and
  eyeball the rest.

## Usage & verification

```
python lua4dec.py input.luab -o output.lua          # decompile (omit -o for stdout)
luac4 -p output.lua                                 # syntax check
luac4 -o rc.luab output.lua                         # recompile
luac4 -l -p input.luab  vs  luac4 -l -p rc.luab     # normalized disasm diff (ground truth)
```
Canonical repo also has `roundtrip_check.py` (all-16 harness, `--baseline baseline_roundtrip.json`) and
`find_dropped_locals.py <file.luab>` (names a dropped `local`). The Lua 4.0.1 toolchain
(`luac4.exe`/`lua4.exe`) is under `../autothief_decomp/tools/lua4-decompile/CFLuaDC-Lua4-Decompiler-main/`.

## This repo is a mirror

The canonical, actively-maintained decompiler is `../autothief_decomp/tools/lua4-decompile/lua4dec.py`. Make changes
there, validate with its harness, then re-sync `lua4dec.py` here. Tag `intro-baseline` (`272713c`) is kept only
because its intro.lua output doesn't hang at load.
