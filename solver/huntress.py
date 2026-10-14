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
import sys
import time

import gamemaster as gm
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


def _solve_one(challenge_id, question, index, single_delivery):
    """Download + decode one question's artifact. Returns a result dict."""
    delivery = None if single_delivery else index
    raw = gm.artifact(challenge_id, delivery=delivery, timeout=30)
    info = extract(raw)
    puzzle = info["puzzle"]
    if puzzle is None:
        # no puzzle json: fall back to any raw ANS- found in the bytes
        if info["raw_answer"] and is_answer(info["raw_answer"]):
            answer, codec = info["raw_answer"], "raw-embedded"
        else:
            raise RuntimeError("no puzzle and no ANS- code in artifact for %s"
                               % question.get("id"))
    else:
        answer, codec = decode(puzzle)

    # sanity: case id embedded in the APK should match the question's case id
    qtext = question.get("question", "")
    case_ok = (info["case_id"] in qtext) if info["case_id"] else None
    return {
        "id": question["id"],
        "answer": answer,
        "codec": codec,
        "case_id": info["case_id"],
        "case_match": case_ok,
        "artifact": question.get("artifact"),
    }


def solve_mode(challenge_id, submit=False, parallel=True, fresh=False):
    """Solve one challenge (single/time/mastery). Returns a report dict."""
    t0 = time.time()
    resp = gm.retry(challenge_id) if fresh else gm.start(challenge_id)
    questions = resp.get("questions", [])
    if not questions:
        return {"challenge": challenge_id, "error": "no questions in start response",
                "raw_result": resp.get("result"), "response": resp}

    single_delivery = len(questions) == 1
    results = [None] * len(questions)

    def work(i):
        return i, _solve_one(challenge_id, questions[i], i, single_delivery)

    if parallel and len(questions) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(questions)) as ex:
            for i, r in ex.map(work, range(len(questions))):
                results[i] = r
    else:
        for i in range(len(questions)):
            _, results[i] = work(i)

    decode_s = time.time() - t0
    answers = {r["id"]: r["answer"] for r in results}

    report = {
        "challenge": challenge_id,
        "start_result": resp.get("result"),
        "attempts_remaining": resp.get("unique_attempts_remaining"),
        "questions": results,
        "answers": answers,
        "decode_seconds": round(decode_s, 2),
    }

    if submit:
        sub = gm.submit(challenge_id, answers)
        report["submit_result"] = sub.get("result")
        report["submit_message"] = sub.get("message")
        report["total_seconds"] = round(time.time() - t0, 2)
        report["remaining"] = sub.get("remaining")
    return report


def _print_report(rep, mode):
    print("\n=== %s  [%s] ===" % (rep["challenge"], mode))
    if rep.get("error"):
        print("  ERROR:", rep["error"], "(start result: %s)" % rep.get("raw_result"))
        return
    print("  start:", rep["start_result"],
          "| attempts_remaining:", rep.get("attempts_remaining"),
          "| decode: %ss" % rep["decode_seconds"])
    for r in rep["questions"]:
        match = {True: "ok", False: "MISMATCH", None: "n/a"}[r["case_match"]]
        print("    %-12s %s  (codec=%s, case=%s match=%s)"
              % (r["id"], r["answer"], r["codec"], r["case_id"], match))
    if "submit_result" in rep:
        print("  SUBMIT:", rep["submit_result"],
              ("| %s" % rep["submit_message"]) if rep.get("submit_message") else "",
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
