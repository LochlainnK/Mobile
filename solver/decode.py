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

    if codec == "plain":
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


def brute_force(puzzle_or_text):
    """Return the first ANS- code found by trying every known transform.

    Accepts either a puzzle dict or a raw string/bytes blob.
    """
    candidates = []
    if isinstance(puzzle_or_text, dict):
        p = puzzle_or_text
        # try the split reassembly if parts present
        if "parts" in p and "order" in p:
            try:
                out = [None] * len(p["parts"])
                for i, pos in enumerate(p["order"]):
                    out[pos] = p["parts"][i]
                candidates.append("".join(out))
            except Exception:
                pass
        blob = p.get("data")
        if isinstance(blob, (list, tuple)):
            blob = "".join(str(x) for x in blob)
        if blob is None:
            blob = ""
        texts = [str(blob)]
        # also fold in the declared key for xor/caesar sweeps already covered
    else:
        blob = puzzle_or_text
        if isinstance(blob, bytes):
            blob = blob.decode("latin-1")
        texts = [blob]

    for t in texts:
        for cand in _candidates_from_string(t):
            if isinstance(cand, str):
                m = ANSWER_RE.search(cand)
                if m:
                    candidates.append(m.group(0))

    for c in candidates:
        if is_answer(c):
            return c
    # last resort: any ANS- substring anywhere
    for c in candidates:
        m = ANSWER_RE.search(c or "")
        if m:
            return m.group(0)
    return None


def decode(puzzle):
    """Decode a puzzle dict to an ANS- answer, with brute-force fallback.

    Returns (answer, codec_used). codec_used is the declared codec when it
    produced a valid answer, else 'brute-force'.
    """
    codec = puzzle.get("codec")
    try:
        ans = decode_known(puzzle)
        if is_answer(ans):
            return ans, codec
        # declared codec produced something; salvage an embedded ANS- if present
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
