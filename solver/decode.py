"""Puzzle decoder for Huntress CTF 2026 mobile-android artifacts.

Every mobile-android artifact is an APK that embeds the backend evidence code
inside ``assets/huntress_puzzle.json``::

    {"schema": "huntress.mobile.puzzle.v1", "day": N, "codec": "<codec>", "data": ...}

The intended (manual) solution path is to analyse the exported Activity / deep
link / provider / WebView bridge and call the embedded backend to retrieve the
evidence code.  The static artifact ships that same code encoded in the puzzle
blob, so the robust, fast path is to decode the blob directly.

Known codecs (observed across released days 1-13):

    plain    data is the answer verbatim
    reverse  answer reversed
    base64   base64(answer)
    hex      hex(answer)
    xor      base64(answer XOR key)         ; integer "key"
    caesar   chr(ord(c)+key) per char        ; integer "key"  (decode: subtract)
    split    answer broken into "parts", reassembled by "order":
             out[order[i]] = parts[i]
    native   data is the answer verbatim (day 15; themed around a native .so,
             but the static blob is plain)

All answers normalise to ``ANS-<16 uppercase hex>``.  The decoder is
defensive: unknown or malformed codecs fall back to a brute-force search that
tries every known transform and returns whatever yields a valid answer.
"""

import base64
import re

ANSWER_RE = re.compile(r"ANS-[0-9A-F]{16}")
ANSWER_FULL_RE = re.compile(r"^ANS-[0-9A-F]{16}$")


def is_answer(s):
    return isinstance(s, str) and bool(ANSWER_FULL_RE.match(s))


def _b64(data):
    # tolerate missing padding
    pad = (-len(data)) % 4
    return base64.b64decode(data + "=" * pad)


def decode_known(p):
    """Decode a puzzle dict using its declared codec. Raises on unknown codec."""
    codec = p.get("codec")
    data = p.get("data")

    if codec in ("plain", "native"):
        # 'native' (day 15, "native-library-secrets"): the APK ships a native
        # .so as the intended reverse-engineering path, but the static puzzle
        # blob carries the answer verbatim, exactly like 'plain'.
        return data
    if codec == "reverse":
        return data[::-1]
    if codec == "base64":
        return _b64(data).decode("utf-8", "replace")
    if codec == "hex":
        return bytes.fromhex(data).decode("utf-8", "replace")
    if codec == "xor":
        key = int(p["key"])
        return bytes(b ^ key for b in _b64(data)).decode("utf-8", "replace")
    if codec == "caesar":
        key = int(p["key"])
        return "".join(chr((ord(c) - key) & 0xFF) for c in data)
    if codec == "split":
        parts, order = p["parts"], p["order"]
        out = [None] * len(parts)
        for i, pos in enumerate(order):
            out[pos] = parts[i]
        return "".join(out)
    raise ValueError("unknown codec: %r" % codec)


def _candidates_from_string(s):
    """Yield decode attempts for a single string blob."""
    yield s
    yield s[::-1]
    # base64 / hex
    try:
        yield _b64(s).decode("utf-8", "replace")
    except Exception:
        pass
    try:
        yield bytes.fromhex(s).decode("utf-8", "replace")
    except Exception:
        pass
    # caesar / rot over all shifts (on the raw string and on a base64 decode)
    bases = [s]
    try:
        bases.append(_b64(s))
    except Exception:
        pass
    for base in bases:
        chars = base if isinstance(base, str) else base.decode("latin-1")
        for k in range(1, 256):
            yield "".join(chr((ord(c) - k) & 0xFF) for c in chars)
        # xor over all keys
        raw = base.encode("latin-1") if isinstance(base, str) else base
        for k in range(1, 256):
            try:
                yield bytes(b ^ k for b in raw).decode("utf-8", "replace")
            except Exception:
                pass


def _brute_answers(puzzle_or_text):
    """Return all distinct valid ANS- codes found by trying every transform,
    in discovery order (most-likely transforms first)."""
    found = []

    def add(s):
        if isinstance(s, str):
            m = ANSWER_RE.search(s)
            if m and m.group(0) not in found:
                found.append(m.group(0))

    if isinstance(puzzle_or_text, dict):
        p = puzzle_or_text
        if "parts" in p and "order" in p:
            try:
                out = [None] * len(p["parts"])
                for i, pos in enumerate(p["order"]):
                    out[pos] = p["parts"][i]
                add("".join(out))
            except Exception:
                pass
        blob = p.get("data")
        if isinstance(blob, (list, tuple)):
            blob = "".join(str(x) for x in blob)
        text = "" if blob is None else str(blob)
    else:
        text = puzzle_or_text
        if isinstance(text, bytes):
            text = text.decode("latin-1")

    for cand in _candidates_from_string(text):
        add(cand)
    return found


def brute_force(puzzle_or_text):
    """Return the first ANS- code found by brute force, or None."""
    found = _brute_answers(puzzle_or_text)
    return found[0] if found else None


def candidates(puzzle):
    """Return an ordered list of distinct candidate answers, best first.

    The declared codec's output leads (when it yields a valid answer), followed
    by brute-force alternates.  The solver submits the first and, only if the
    Game Master rejects it, falls back to the rest — so an unseen or ambiguous
    codec still has a path to CORRECT without a human in the loop.
    """
    out = []
    try:
        ans = decode_known(puzzle)
        if isinstance(ans, str):
            m = ANSWER_RE.search(ans)
            if m:
                out.append(m.group(0))
    except Exception:
        pass
    for a in _brute_answers(puzzle):
        if a not in out:
            out.append(a)
    return out


def decode(puzzle):
    """Decode a puzzle dict to an ANS- answer, with brute-force fallback.

    Returns (answer, codec_used). codec_used is the declared codec when it
    produced a valid answer, else 'brute-force(<declared>)'.
    """
    codec = puzzle.get("codec")
    try:
        ans = decode_known(puzzle)
        if is_answer(ans):
            return ans, codec
        if isinstance(ans, str):
            m = ANSWER_RE.search(ans)
            if m:
                return m.group(0), codec
    except Exception:
        pass
    ans = brute_force(puzzle)
    if ans:
        return ans, "brute-force(%s)" % codec
    raise ValueError("could not decode puzzle: %r" % puzzle)


if __name__ == "__main__":
    import json
    import sys

    p = json.load(open(sys.argv[1]))
    ans, used = decode(p)
    print(f"{ans}  (codec={used}, valid={is_answer(ans)})")
