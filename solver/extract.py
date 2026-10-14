"""Pull the puzzle (and useful metadata) out of a downloaded artifact.

Artifacts are APKs (ZIP containers).  Should a future day wrap the APK in a
password-protected archive, the password is ``infected`` (per event
convention); we try it automatically.  The puzzle normally lives at
``assets/huntress_puzzle.json`` but we also fall back to scanning every member
for a ``huntress_puzzle.json`` and, failing that, for a raw ``ANS-`` code.
"""

import io
import json
import re
import subprocess
import tempfile
import zipfile

PUZZLE_NAME = "huntress_puzzle.json"
ANSWER_RE = re.compile(rb"ANS-[0-9A-F]{16}")
CASE_RE = re.compile(rb"MOB-\d{2}-[0-9A-F]+")
PASSWORD = b"infected"


def _open_zip(data):
    """Return a ZipFile for the bytes, handling the 'infected' password."""
    zf = zipfile.ZipFile(io.BytesIO(data))
    # Probe whether reading needs a password.
    names = [n for n in zf.namelist() if not n.endswith("/")]
    if names:
        try:
            zf.read(names[0])
            return zf, None  # no password needed
        except RuntimeError:
            zf.setpassword(PASSWORD)  # ZipCrypto
            try:
                zf.read(names[0])
                return zf, PASSWORD
            except (RuntimeError, NotImplementedError):
                pass
    else:
        return zf, None
    # AES or other: fall back to the `unzip` CLI with the password.
    return None, PASSWORD


def _unzip_cli(data):
    """Extract a password-protected archive via the unzip CLI, return {name: bytes}."""
    out = {}
    with tempfile.TemporaryDirectory() as td:
        arc = td + "/artifact.zip"
        with open(arc, "wb") as fh:
            fh.write(data)
        subprocess.run(["unzip", "-o", "-P", PASSWORD.decode(), arc, "-d", td + "/ex"],
                       capture_output=True)
        import os
        for root, _dirs, files in os.walk(td + "/ex"):
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, td + "/ex")
                with open(full, "rb") as fh:
                    out[rel] = fh.read()
    return out


def _members(data):
    """Return {name: bytes} for all files in the artifact, handling passwords
    and nested archives one level deep."""
    members = {}
    zf, _pw = _open_zip(data)
    if zf is None:
        members = _unzip_cli(data)
    else:
        for n in zf.namelist():
            if n.endswith("/"):
                continue
            try:
                members[n] = zf.read(n)
            except RuntimeError:
                zf.setpassword(PASSWORD)
                members[n] = zf.read(n)
    # Nested archive (e.g. a .zip containing the real .apk)?
    if not any(PUZZLE_NAME in n for n in members):
        for n, b in list(members.items()):
            if b[:2] == b"PK" and (n.endswith(".apk") or n.endswith(".zip")):
                try:
                    inner = _members(b)
                    members.update({n + "!" + k: v for k, v in inner.items()})
                except Exception:
                    pass
    return members


def extract(data):
    """Return dict with puzzle (parsed json or None), case_id, raw_answer, members."""
    members = _members(data)

    puzzle = None
    for name, blob in members.items():
        if name.endswith(PUZZLE_NAME):
            try:
                puzzle = json.loads(blob)
                break
            except Exception:
                pass

    # case id and any raw ANS- from the dex / any member
    case_id = None
    raw_answer = None
    for name, blob in members.items():
        if case_id is None:
            m = CASE_RE.search(blob)
            if m:
                case_id = m.group(0).decode()
        if raw_answer is None:
            m = ANSWER_RE.search(blob)
            if m:
                raw_answer = m.group(0).decode()

    return {
        "puzzle": puzzle,
        "case_id": case_id,
        "raw_answer": raw_answer,
        "members": list(members.keys()),
        "_blobs": members,
    }
