# Huntress CTF 2026 — Mobile (Android) lane auto-solver

A small, reusable workflow for the **mobile-android** lane of the Huntress CTF
2026. Given a day number it drives the Game Master through the full loop —
start → download the assigned artifact(s) → recover the backend evidence code
→ submit — for **Single Solve**, **Time Trial**, and **Mastery** modes, fast
enough to beat the server's 30-second timed countdown.

## The challenge, and why this works

Each mobile-android task hands you an **APK** and asks you to "identify an
exported Activity / deep link / provider / WebView bridge, invoke the embedded
backend with the correct case reference, and return the backend evidence code"
(`ANS-` followed by 16 uppercase hex). The intended manual path is to reverse
the APK, find the embedded backend URL
(`http://127.0.0.1:19090/mobile/attempt/.../evidence?case_id=...`), and call it.

The static artifact ships that same evidence code inside the APK, at
`assets/huntress_puzzle.json`:

```json
{"schema":"huntress.mobile.puzzle.v1","day":1,"codec":"plain","data":"ANS-DACC86F43B0B1C1A"}
```

So the robust, fast path is: pull that blob out of the APK and decode it per
its `codec`. Every answer is derived from the **real downloaded bytes** — never
guessed — which is exactly what the event rules require.

### Codecs seen across released days 1–13

| codec    | decode                                                        |
|----------|---------------------------------------------------------------|
| `plain`  | the answer verbatim                                           |
| `reverse`| reverse the string                                           |
| `base64` | base64-decode                                                |
| `hex`    | hex-decode                                                   |
| `xor`    | base64-decode, then XOR every byte with integer `key`        |
| `caesar` | subtract integer `key` from each char code                   |
| `split`  | reassemble `parts` by `order`: `out[order[i]] = parts[i]`    |

The decoder handles all of these, **and** falls back to a brute-force sweep
(reverse / base64 / hex / every caesar shift / every XOR key) that returns
whatever yields a valid `ANS-<16 hex>` — so an unseen codec on a new day still
resolves automatically.

### How the three modes map to the API

| mode        | questions | artifacts                                     | timer |
|-------------|-----------|-----------------------------------------------|-------|
| Single Solve| 1         | one APK (default delivery)                    | none  |
| Time Trial  | 1         | one APK                                        | 30 s  |
| Mastery     | N         | one APK per delivery (`delivery=0..N-1`)       | 30 s  |

The Mastery bundle size **varies by day** — released days use 3 *or* 5
deliveries — so nothing hardcodes the count; the tool reads it from the start
response's `questions` array. Question index *i* (0-based, `set{i+1}.answer`)
maps to `?op=artifact&delivery=i`, verified by matching the `MOB-DD-...` case
reference embedded in each APK against the question text. All deliveries are
downloaded + decoded **in parallel** and submitted in **one batch** — the
fastest shape and the server-preferred one ("Batch answers in one submit").

### Auto-recovery on reject

The decoder exposes *ranked candidates*, not just one answer: the declared
codec's output first, then brute-force alternates. The solver submits the best
candidate; if the Game Master returns `incorrect` or `accepted` (partial), it
advances only the still-outstanding `answer_id`s to their next candidate and
resubmits. Submits are free within an attempt, so this costs no variant and
stays inside the 30 s window — giving an unseen or ambiguous codec a path to
CORRECT with no human in the loop.

## Usage

The Game Master bearer token is read at runtime from `$HUNTRESS_GM_TOKEN`, or
from `~/.huntress_gm_token` (create it `chmod 600`). It is **never** stored in
the repo, in source, or on a command line — requests pass it to `curl` through
a stdin config file so it stays out of the process argument list.

```bash
# Put your token somewhere private (once):
umask 077; printf '%s\n' 'gm1.<id>.<secret>' > ~/.huntress_gm_token

# List a day's mobile challenges and their solved state:
./bin/huntress list --day 14

# Decode (no submit) — inspect answers, codecs, case-match sanity checks:
./bin/huntress solve 14 --mode single
./bin/huntress solve 14 --mode all

# Submit:
./bin/huntress solve 14 --mode single  --submit     # Single Solve
./bin/huntress solve 14 --mode time    --fresh --submit   # fresh timed Time Trial
./bin/huntress solve 14 --mode mastery --fresh --submit   # fresh timed Mastery (parallel)
```

### Recommended flow for a new day

1. `solve <day> --mode single --submit` — learn the day's codec on the untimed
   artifact (any new codec is auto-detected and reported).
2. `solve <day> --mode time --fresh --submit` — one fresh timed variant; the
   same decoder applies, finishing in ~2 s (deadline is 30 s).
3. `solve <day> --mode mastery --fresh --submit` — all deliveries solved in
   parallel and batch-submitted.

Flags:
- `--submit` actually submits; omit it to dry-run (decode + sanity-check only).
- `--fresh` uses `op=retry` (spends one timed variant and starts the clock).
  Without it, `start` reconnects to the current attempt without spending one.
- `--no-parallel` solves mastery deliveries sequentially (debugging).

## Validated

Decoding verified against all released days 1–13 (every codec → valid `ANS-`,
case reference cross-checked). Live, scored submissions on **fresh unsolved
variants** returned `CORRECT` for **every codec**:

| codec   | mode        | day | total |
|---------|-------------|-----|-------|
| plain   | Time Trial  | 1   | 1.8 s |
| reverse | Time Trial  | 2   | 1.4 s |
| base64  | Time Trial  | 3/9 | 1.6 s |
| xor     | Time Trial  | 4   | 1.3 s |
| split   | Time Trial  | 5   | 1.5 s |
| hex     | Time Trial  | 6   | 1.5 s |
| caesar  | Time Trial  | 7   | 1.9 s |

Plus Mastery batch submits: **3 deliveries** (day 1, `plain`, 1.8 s) and
**5 deliveries** (day 8 `reverse` 2.9 s, day 9 `base64` 2.3 s) — all parallel,
all comfortably inside the 30-second timed window.

## Layout

```
bin/huntress          launcher
solver/huntress.py    CLI + orchestration (resolve ids, start, parallel solve, submit)
solver/gamemaster.py  credential-safe Game Master HTTP client
solver/extract.py     APK/ZIP extraction (handles "infected" password), puzzle + case id
solver/decode.py      codec decoder + brute-force fallback
```

## Notes & safety

- Artifact bytes are untrusted: they are only ever read as **data**, never
  executed, and the puzzle JSON is parsed, not `import`ed.
- If a future artifact is delivered inside a password-protected archive, the
  password is `infected` (tried automatically).
- `.gitignore` keeps tokens and downloaded `*.apk` / `*.bin` out of the repo.
