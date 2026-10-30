#!/usr/bin/env python3
"""Huntress CTF 2026 — mobile-android lane auto-solver.

Workflow (see README.md for the full writeup)::

    huntress.py list [--day N]
    huntress.py solve <day> [--mode single|time|mastery|all] [--submit]

For each selected challenge the tool runs the full loop against the Game
Master: start -> download assigned artifact(s) -> decode the embedded puzzle to
the ANS- evidence code -> (optionally) submit.  Mastery bundles several
deliveries behind one timer; they are downloaded + decoded in parallel and then
submitted in a single batch, which is both the fastest and the server-preferred
shape ("Batch answers in one submit by default").

Nothing here guesses: every answer is derived from the real downloaded bytes.
"""

import argparse
import concurrent.futures
import hashlib
import sys
import time

import gamemaster as gm
from decode import candidates as decode_candidates
from decode import decode, is_answer
from extract import extract

MODE_SUFFIX = {"single": "", "time": "/time_trial", "mastery": "/mastery"}
MODE_ORDER = ["single", "time", "mastery"]


def resolve_ids(day):
    """Return {mode: challenge_id} for a mobile-android day via op=list."""
    data = gm.list_challenges(day=day, lane="mobile")
    base = None
    for c in data.get("challenges", []):
        if c.get("lane") == "mobile-android" and c.get("mode") == "single_solve":
            base = c["id"]
            break
    if not base:
        # fall back: any mobile id for the day, strip a known suffix
        for c in data.get("challenges", []):
            if c.get("lane") == "mobile-android":
                base = c["id"].split("/")[0]
                break
    if not base:
        raise SystemExit("No mobile-android challenge found for day %s" % day)
    return {m: base + suf for m, suf in MODE_SUFFIX.items()}


def _fetch_artifact(challenge_id, question, index, single_delivery, resp):
    """Fetch one question's artifact bytes, preferring the capability download.

    Newer timed routes (day 14+) serve the artifact only through a one-time
    ``download`` capability (``/?op=download&capability=...``) carried on the
    question (or, for a single-question attempt, at the top level) alongside a
    ``sha256``.  Older routes serve it via ``op=artifact[&delivery=i]``.  The
    hash is verified whenever the server provides one.
    """
    dl = question.get("download") or (resp.get("download") if single_delivery else None)
    sha = question.get("sha256") or (resp.get("sha256") if single_delivery else None)
    if dl:
        raw = gm.download(dl, timeout=30)
    else:
        delivery = None if single_delivery else index
        raw = gm.artifact(challenge_id, delivery=delivery, timeout=30)
    if sha:
        actual = hashlib.sha256(raw).hexdigest()
        if actual != sha:
            raise RuntimeError("sha256 mismatch for %s (got %s, want %s)"
                               % (question.get("id"), actual[:12], sha[:12]))
    return raw


def _solve_one(challenge_id, question, index, single_delivery, resp):
    """Download + decode one question's artifact. Returns a result dict with an
    ordered list of candidate answers (best first) for retry-on-reject."""
    raw = _fetch_artifact(challenge_id, question, index, single_delivery, resp)
    info = extract(raw)
    puzzle = info["puzzle"]
    members = info.get("_blobs")
    if puzzle is None:
        # no puzzle json: fall back to any raw ANS- found in the bytes
        if info["raw_answer"] and is_answer(info["raw_answer"]):
            answer, codec, cands = info["raw_answer"], "raw-embedded", [info["raw_answer"]]
        else:
            raise RuntimeError("no puzzle and no ANS- code in artifact for %s"
                               % question.get("id"))
    else:
        answer, codec = decode(puzzle, members)
        cands = decode_candidates(puzzle, members) or [answer]
        if answer not in cands:
            cands.insert(0, answer)

    # sanity: case id embedded in the APK should match the question's case id
    qtext = question.get("question", "")
    case_ok = (info["case_id"] in qtext) if info["case_id"] else None
    return {
        "id": question["id"],
        "answer": answer,
        "candidates": cands,
        "cand_index": 0,
        "codec": codec,
        "case_id": info["case_id"],
        "case_match": case_ok,
        "artifact": question.get("artifact"),
    }


def _begin(challenge_id, fresh):
    """Obtain a usable, downloadable attempt.

    Tries start (or retry when fresh); if the attempt is expired/absent or the
    server points to untimed play (``next_op: "practice"`` / exhausted ranked
    variants), falls back to ``op=practice`` — waiting out any still-live timed
    attempt (``attempt_active``) so the mode can always be completed.
    """
    resp = gm.retry(challenge_id) if fresh else gm.start(challenge_id)
    need_practice = (
        not resp.get("questions")
        or resp.get("result") in ("expired",)
        or resp.get("error") in ("start_required", "attempt_expired")
        or resp.get("next_op") == "practice"
    )
    if need_practice:
        for _ in range(15):
            p = gm.practice(challenge_id)
            if p.get("error") == "attempt_active":
                time.sleep(3)
                continue
            if p.get("questions"):
                return p
            break
    return resp


def solve_mode(challenge_id, submit=False, parallel=True, fresh=False):
    """Solve one challenge (single/time/mastery). Returns a report dict."""
    t0 = time.time()
    resp = _begin(challenge_id, fresh)
    if resp.get("error"):
        return {"challenge": challenge_id, "error": resp["error"],
                "message": resp.get("message")}
    questions = resp.get("questions", [])
    if not questions:
        return {"challenge": challenge_id, "error": "no questions in start response",
                "raw_result": resp.get("result") or resp.get("error"), "response": resp}

    single_delivery = len(questions) == 1
    results = [None] * len(questions)

    def work(i):
        try:
            return i, _solve_one(challenge_id, questions[i], i, single_delivery, resp)
        except Exception as e:  # one blocked delivery must not crash the batch
            return i, {"id": questions[i].get("id"), "answer": None,
                       "candidates": [], "cand_index": 0, "codec": None,
                       "case_id": None, "case_match": None,
                       "artifact": questions[i].get("artifact"), "error": str(e)}

    if parallel and len(questions) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(questions)) as ex:
            for i, r in ex.map(work, range(len(questions))):
                results[i] = r
    else:
        for i in range(len(questions)):
            _, results[i] = work(i)

    decode_s = time.time() - t0
    answers = {r["id"]: r["answer"] for r in results if r.get("answer")}
    blocked = [r for r in results if not r.get("answer")]

    report = {
        "challenge": challenge_id,
        "start_result": resp.get("result"),
        "attempts_remaining": resp.get("unique_attempts_remaining"),
        "questions": results,
        "answers": answers,
        "decode_seconds": round(decode_s, 2),
    }
    if blocked:
        report["blocked"] = [{"id": r.get("id"), "error": r.get("error")} for r in blocked]

    if submit and answers and not blocked:
        sub = gm.submit(challenge_id, answers)
        result = sub.get("result")
        attempts = [{"answers": dict(answers), "result": result}]

        # Auto-recover: if the Game Master rejects some answers (a wrong decode
        # on an unseen/ambiguous codec), advance those answer_ids to their next
        # brute-force candidate and resubmit only the ones still outstanding.
        # Submits are free within an attempt; this stays well inside the timer.
        by_id = {r["id"]: r for r in results}
        rounds = 0
        while (result in ("incorrect", "accepted")) and rounds < 8:
            failing = _failing_ids(sub, answers)
            retry = {}
            for qid in failing:
                r = by_id.get(qid)
                if not r:
                    continue
                r["cand_index"] += 1
                if r["cand_index"] < len(r["candidates"]):
                    retry[qid] = r["candidates"][r["cand_index"]]
            if not retry:
                break
            answers = retry  # only resubmit the outstanding ids
            sub = gm.submit(challenge_id, answers)
            result = sub.get("result")
            attempts.append({"answers": dict(answers), "result": result})
            rounds += 1

        report["submit_result"] = result
        report["submit_message"] = sub.get("message")
        report["submit_attempts"] = attempts
        report["total_seconds"] = round(time.time() - t0, 2)
        report["remaining"] = sub.get("remaining")
    return report


def _failing_ids(sub, submitted):
    """Best-effort set of answer_ids the Game Master has not accepted yet.

    Handles the documented shapes: an explicit list of outstanding ids under
    'remaining'/'incorrect'/'pending', or — for a single wrong answer — the one
    id just submitted.  Falls back to every submitted id.
    """
    for key in ("remaining", "incorrect", "pending", "unsolved"):
        val = sub.get(key)
        if isinstance(val, list) and val and all(isinstance(x, str) for x in val):
            return [x for x in val if x in submitted]
        if isinstance(val, dict):
            return [x for x in val if x in submitted]
    return list(submitted)


def _print_report(rep, mode):
    print("\n=== %s  [%s] ===" % (rep["challenge"], mode))
    if rep.get("error") and "questions" not in rep:
        msg = rep.get("message") or rep.get("raw_result")
        print("  BLOCKED:", rep["error"], ("- %s" % msg) if msg else "")
        return
    print("  start:", rep["start_result"],
          "| attempts_remaining:", rep.get("attempts_remaining"),
          "| decode: %ss" % rep["decode_seconds"])
    for r in rep["questions"]:
        if not r.get("answer"):
            print("    %-12s BLOCKED: %s" % (r.get("id"), r.get("error")))
            continue
        match = {True: "ok", False: "MISMATCH", None: "n/a"}[r["case_match"]]
        print("    %-12s %s  (codec=%s, case=%s match=%s)"
              % (r["id"], r["answer"], r["codec"], r["case_id"], match))
    if "submit_result" in rep:
        n = len(rep.get("submit_attempts", []))
        print("  SUBMIT:", rep["submit_result"],
              ("| %s" % rep["submit_message"]) if rep.get("submit_message") else "",
              ("| %d submit rounds" % n) if n > 1 else "",
              "| total: %ss" % rep.get("total_seconds"))


def cmd_list(args):
    data = gm.list_challenges(day=args.day, lane="mobile")
    print(data.get("message", ""))
    rows = [c for c in data.get("challenges", []) if c.get("lane") == "mobile-android"]
    rows.sort(key=lambda c: (c["day"], c["mode"]))
    for c in rows:
        print("  d%02d  %-13s %-10s %s"
              % (c["day"], c["mode"], "solved" if c.get("solved") else "unsolved", c["id"]))


def cmd_solve(args):
    ids = resolve_ids(args.day)
    modes = MODE_ORDER if args.mode == "all" else [args.mode]
    for mode in modes:
        rep = solve_mode(ids[mode], submit=args.submit,
                         parallel=not args.no_parallel, fresh=args.fresh)
        _print_report(rep, mode)
        # For "all", stop if a submit failed outright.
        if args.submit and rep.get("submit_result") == "incorrect":
            print("  (stopping: incorrect submission)")
            break


def main(argv=None):
    p = argparse.ArgumentParser(description="Huntress CTF 2026 mobile auto-solver")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("list", help="list mobile challenges")
    pl.add_argument("--day", type=int, default=None)
    pl.set_defaults(func=cmd_list)

    ps = sub.add_parser("solve", help="solve a mobile day")
    ps.add_argument("day", type=int)
    ps.add_argument("--mode", choices=["single", "time", "mastery", "all"],
                    default="single")
    ps.add_argument("--submit", action="store_true", help="submit decoded answers")
    ps.add_argument("--fresh", action="store_true",
                    help="use op=retry (spends one timed variant) instead of reconnecting")
    ps.add_argument("--no-parallel", action="store_true")
    ps.set_defaults(func=cmd_solve)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
