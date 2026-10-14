"""Thin, credential-safe client for the Huntress CTF 2026 Game Master API.

The bearer token is read at runtime from ``$HUNTRESS_GM_TOKEN`` or the private
file ``~/.huntress_gm_token`` (chmod 600).  It is NEVER embedded in source, in
command-line arguments, or in any committed file.  Requests use ``curl
--config -`` with the ``Authorization`` header piped over stdin, which keeps the
bearer out of the process argument list (and therefore out of ``ps`` / logs).

API (see ``?op=openapi``):

    GET  ?op=list[&day=N][&lane=mobile][&all=true]
    GET  ?op=status&challenge=<id>
    GET  ?op=artifact&challenge=<id>[&delivery=N]
    POST {"op":"start","challenge":"<id>"}
    POST {"op":"submit","challenge":"<id>","answers":{"<answer_id>":"<ANS->"}}
    POST {"op":"retry","challenge":"<id>"}          # spends one timed variant
"""

import json
import os
import subprocess
import tempfile

BASE_URL = "https://2026.huntress.ctf.games/"
TOKEN_FILE = os.path.expanduser("~/.huntress_gm_token")


def _token():
    tok = os.environ.get("HUNTRESS_GM_TOKEN")
    if tok:
        return tok.strip()
    try:
        with open(TOKEN_FILE) as fh:
            return fh.read().strip()
    except FileNotFoundError:
        raise SystemExit(
            "No Game Master token. Set $HUNTRESS_GM_TOKEN or create %s (chmod 600)."
            % TOKEN_FILE
        )


def _curl(url, post_body=None, raw=False, timeout=60):
    """Run curl with the bearer supplied via a stdin config file (never in argv).

    For POSTs the JSON body is written to a temp file and referenced with
    ``--data-binary @file`` so the body (which is harmless) is off argv too and
    there is no config-file escaping to get wrong.  Only the Authorization
    header carries the secret, and it lives solely in the stdin config stream.
    """
    config = 'header = "Authorization: Bearer %s"\n' % _token()
    cmd = ["curl", "-sS", "--max-time", str(timeout)]
    body_file = None
    try:
        if post_body is not None:
            data = post_body if isinstance(post_body, str) else json.dumps(post_body)
            fd, body_file = tempfile.mkstemp(prefix="gm_body_", suffix=".json")
            with os.fdopen(fd, "w") as fh:
                fh.write(data)
            cmd += ["-H", "Content-Type: application/json",
                    "-X", "POST", "--data-binary", "@" + body_file]
        cmd += ["--config", "-", url]
        proc = subprocess.run(cmd, input=config.encode(), capture_output=True)
    finally:
        if body_file:
            try:
                os.unlink(body_file)
            except OSError:
                pass
    if proc.returncode != 0:
        raise RuntimeError("curl failed (%d): %s" % (
            proc.returncode, proc.stderr.decode("utf-8", "replace")))
    return proc.stdout if raw else proc.stdout.decode("utf-8", "replace")


def _get(params, raw=False, timeout=60):
    from urllib.parse import urlencode
    return _curl(BASE_URL + "?" + urlencode(params), raw=raw, timeout=timeout)


def _post(body, timeout=60):
    out = _curl(BASE_URL, post_body=body, timeout=timeout)
    return json.loads(out)


# ---- public API ----------------------------------------------------------

def list_challenges(day=None, lane=None, all_days=False, search=None):
    params = {"op": "list"}
    if day is not None:
        params["day"] = str(day)
    if lane:
        params["lane"] = lane
    if all_days:
        params["all"] = "true"
    if search:
        params["search"] = search
    return json.loads(_get(params))


def status(challenge):
    return json.loads(_get({"op": "status", "challenge": challenge}))


def artifact(challenge, delivery=None, timeout=60):
    """Download raw artifact bytes. delivery selects a mastery sub-task (0-based)."""
    params = {"op": "artifact", "challenge": challenge}
    if delivery is not None:
        params["delivery"] = str(delivery)
    return _get(params, raw=True, timeout=timeout)


def start(challenge, run_for_time=False):
    body = {"op": "start", "challenge": challenge}
    if run_for_time:
        body["run_for_time"] = True
    return _post(body)


def retry(challenge, run_for_time=False):
    body = {"op": "retry", "challenge": challenge}
    if run_for_time:
        body["run_for_time"] = True
    return _post(body)


def submit(challenge, answers):
    return _post({"op": "submit", "challenge": challenge, "answers": answers})
