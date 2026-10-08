"""Human CLI for co_v4.task: setup / run / resume / status / routes / decide.

Exactly one JSON object on stdout; bounded progress on stderr.  Exit 0
only when the task verified (or setup/status/decide succeeded); failures
are nonzero.  ``decide`` only records an already-presented user choice
for a paused task; it performs no inference and its success does not
mean the task verified -- resume separately.  SIGTERM/SIGINT unwind
infer/verifier cleanup; an interrupted run stays resumable and never
claims a confirmed stop.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path

from . import infer as _infer
from . import runner
from . import select as _select
from .common import TaskError, canonical

_ROLES = ("planner", "design", "implement", "review")
_CATEGORIES = ("coding", "review", "research", "architecture_planning",
               "reasoning", "writing", "general")
_ROUTES2_HELP = ("Run setup for this state directory; it creates routes2.json "
                 "and preserves routes.json.")


def _sigterm(signum, frame):
    raise KeyboardInterrupt


def _code(e):
    return getattr(e, "code", None) or (e.args[0] if e.args else "internal_error")


def _parser():
    p = argparse.ArgumentParser(prog="co_v4.task")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--state-dir", required=True)
    s.add_argument("--native-cwd", required=True)
    s.add_argument("--timeout", type=int, default=180)
    s.add_argument("--legacy", action="store_true",
                   help="probe the legacy routes.json registry instead")
    r = sub.add_parser("run")
    r.add_argument("--state-dir", required=True)
    r.add_argument("--repo", required=True)
    r.add_argument("--goal", required=True)
    r.add_argument("--base", default="HEAD")
    r.add_argument("--read", action="append", default=[])
    r.add_argument("--write", action="append", default=[])
    r.add_argument("--max-steps", type=int, default=6)
    r.add_argument("--max-repairs", type=int, default=1)
    r.add_argument("--call-timeout", type=int, default=900)
    r.add_argument("--mode", choices=("suitability", "usage", "fixed"),
                   default="suitability")
    r.add_argument("--focus", choices=_CATEGORIES,
                   default="architecture_planning")
    r.add_argument("--quiet", action="store_true")
    r.add_argument("--model", action="append", default=[],
                   metavar="ROLE=[ROUTE/]MODEL",
                   help="pin a role to its registered model id (exact match)")
    r.add_argument("--verify", nargs=argparse.REMAINDER, required=True,
                   help="verifier argv; put all other run flags before it")
    rt = sub.add_parser("routes")
    rtsub = rt.add_subparsers(dest="routes_cmd", required=True)
    a = rtsub.add_parser("add")
    a.add_argument("--state-dir", required=True)
    a.add_argument("--native-cwd", required=True)
    a.add_argument("--route", choices=("claude", "devin"), required=True)
    a.add_argument("--model", required=True)
    a.add_argument("--timeout", type=int, default=180)
    a.add_argument("--reprobe", action="store_true")
    f = rtsub.add_parser("fit")
    f.add_argument("--state-dir", required=True)
    f.add_argument("--route", choices=("claude", "devin"), required=True)
    f.add_argument("--model", required=True)
    f.add_argument("--category", choices=_CATEGORIES, required=True)
    f.add_argument("--degree", type=int, choices=(1, 2, 3), default=None)
    f.add_argument("--origin", choices=("prior", "measured"), default="prior")
    f.add_argument("--source-ref", required=True)
    h = rtsub.add_parser("show")
    h.add_argument("--state-dir", required=True)
    for name in ("resume", "status"):
        q = sub.add_parser(name)
        q.add_argument("--state-dir", required=True)
        q.add_argument("--task", required=True)
    d = sub.add_parser("decide")
    d.add_argument("--state-dir", required=True)
    d.add_argument("--task", required=True)
    d.add_argument("--pause-id", required=True)
    d.add_argument("--report-sha256", required=True,
                   help="report_sha256 from the pause report, verbatim "
                        "(keeps the literal sha256: prefix)")
    d.add_argument("--option-id", required=True)
    d.add_argument("--confirm-override", action="store_true",
                   help="confirm an option marked requires_override; also "
                        "accepted, without added authority, on options "
                        "that do not require it")
    return p


def _verify_argv(raw):
    argv = list(raw)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv or not os.path.isabs(argv[0]):
        raise TaskError("verify_argv_invalid")
    return argv  # verbatim, never through a shell


def _task_code(out):
    return 0 if out.get("verified") or out.get("status") in (
        "ok", "verified") else 1


def _emit(text):
    sys.stderr.write(text + "\n")


def _pause_menu(pause, options):
    _emit("decision required: task %s call %s attempt %s "
          "(role=%s focus=%s phase=%s code=%s)"
          % (pause.get("task_id"), pause.get("call_id"),
             pause.get("attempt_id"), pause.get("role"),
             pause.get("focus"), pause.get("phase"), pause.get("code")))
    _emit("outcome=%s process_outcome=%s quota=%s"
          % (pause.get("outcome"), pause.get("process_outcome"),
             pause.get("quota") or "unknown"))
    if pause.get("outcome") == "unknown":
        _emit("the prior result and process state are unconfirmed; "
              "quota is unknown and no retry or switch is available")
        for cand in pause.get("candidates") or []:
            if isinstance(cand, dict):
                _emit("  candidate (information only): %s/%s"
                      % (cand.get("route"), cand.get("model")))
    for index, opt in enumerate(options, 1):
        line = "  %d) %s/%s" % (index, opt.get("route"), opt.get("model"))
        if opt.get("requires_override"):
            line += "  [differs from the pinned selection]"
        _emit(line)
    if pause.get("cancel"):
        _emit("  c) cancel: ends this CO task; does NOT mean the old "
              "request stopped")
    _emit("  0) defer: leave the task pending")


def _readline():
    line = sys.stdin.readline(256)
    return line.strip() if line.endswith("\n") else ""


def _settle(state, task_id, native, out):
    """Resolve awaiting_decision reports; a defer leaves pending unchanged."""
    if out.get("status") != "awaiting_decision":
        return out, _task_code(out)
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        return out, 75
    while out.get("status") == "awaiting_decision":
        pause = out.get("pause") or {}
        tid = pause.get("task_id") or task_id
        options = pause.get("options") or []
        _pause_menu(pause, options)
        _emit("choice (1-%d, 0 defer%s): "
              % (len(options), ", c cancel" if pause.get("cancel") else ""))
        sys.stderr.flush()
        try:
            choice = _readline()
        except KeyboardInterrupt:
            return out, 75
        if not choice or choice == "0":
            return out, 75
        confirm = False
        if choice.lower() == "c":
            if not pause.get("cancel"):
                return out, 75
            option_id = "cancel"
        else:
            try:
                index = int(choice)
            except ValueError:
                return out, 75
            if not 1 <= index <= len(options):
                return out, 75
            opt = options[index - 1]
            option_id = opt.get("option_id")
            if opt.get("requires_override"):
                sel = pause.get("selection") or {}
                _emit("this choice differs from the pinned selection:")
                _emit("  previous attempt: %s/%s (mode %s)"
                      % (sel.get("route"), sel.get("model"),
                         sel.get("mode")))
                _emit("  new for call %s (role %s): %s/%s"
                      % (pause.get("call_id"), pause.get("role"),
                         opt.get("route"), opt.get("model")))
                _emit("  applies to the next one attempt only; later role "
                      "assignments are unchanged")
                _emit("type yes to confirm: ")
                sys.stderr.flush()
                try:
                    answer = _readline()
                except KeyboardInterrupt:
                    return out, 75
                if answer != "yes":
                    return out, 75
                confirm = True
        runner.decide_task(state, tid, pause.get("pause_id"),
                           pause.get("report_sha256"), option_id,
                           confirm_override=confirm)
        out = runner.resume_task(state, tid, native)
    return out, _task_code(out)


def main(argv=None):
    raw = list(sys.argv[1:] if argv is None else argv)
    # argparse consumes a literal -- even in an optional REMAINDER. The
    # verifier owns every argument after --verify, including that token.
    if raw[:1] == ["run"] and "--verify" in raw:
        boundary = raw.index("--verify")
        args = _parser().parse_args(raw[:boundary] + ["--verify"])
        args.verify = raw[boundary + 1:]
    else:
        args = _parser().parse_args(raw)
    signal.signal(signal.SIGTERM, _sigterm)
    try:
        state = Path(args.state_dir)
        if args.cmd == "setup":
            if args.legacy:
                reg = _infer.setup_routes(state, Path(args.native_cwd),
                                          timeout=args.timeout)
            else:
                reg = _select.setup_candidates(state, Path(args.native_cwd),
                                               timeout=args.timeout)
            out, code = {"status": "ok", "routes": reg}, 0
        elif args.cmd == "routes":
            if args.routes_cmd == "add":
                _select.add_candidate(state, Path(args.native_cwd),
                                      args.route, args.model,
                                      timeout=args.timeout,
                                      reprobe=args.reprobe)
            elif args.routes_cmd == "fit":
                _select.set_fit(state, args.route, args.model, args.category,
                                degree=args.degree, origin=args.origin,
                                source_ref=args.source_ref)
            out, code = ({"status": "ok",
                          "routes": _select.show_catalog(state)}, 0)
        elif args.cmd == "status":
            out, code = ({"status": "ok",
                          "task": runner.status_task(state, args.task)}, 0)
        elif args.cmd == "decide":
            out = runner.decide_task(state, args.task, args.pause_id,
                                     args.report_sha256, args.option_id,
                                     confirm_override=args.confirm_override)
            code = 0
        elif args.cmd == "run":
            if not os.path.lexists(state / "routes2.json"):
                out, code = ({"status": "error",
                              "error": {"code": "routing_setup_required",
                                        "help": _ROUTES2_HELP}}, 2)
            else:
                candidates = _select.NativeCandidates(state)
                spec = {"schema": "co.task/3", "goal": args.goal,
                        "repo": str(Path(args.repo).resolve()),
                        "base": args.base,
                        "readable": list(args.read),
                        "writable": list(args.write),
                        "verify": _verify_argv(args.verify),
                        "max_steps": args.max_steps,
                        "max_repairs": args.max_repairs,
                        "call_timeout": args.call_timeout,
                        "focus": args.focus,
                        "announcement": "quiet" if args.quiet else "standard",
                        "selection": {"mode": args.mode,
                                      "targets": candidates.resolve_targets(
                                          args.model)}}
                out = runner.run_task(state, spec, candidates)
                pause = out.get("pause") or {}
                out, code = _settle(state, pause.get("task_id"),
                                    candidates, out)
        else:  # resume
            schema = runner.task_schema(state, args.task)
            if schema == "co.task/1":
                native = _infer.NativeRoutes(state)
            elif schema in ("co.task/2", "co.task/3"):
                native = _select.NativeCandidates(state)
            else:
                raise TaskError("task_schema_unknown")
            out = runner.resume_task(state, args.task, native)
            out, code = _settle(state, args.task, native, out)
    except TaskError as e:
        out, code = {"status": "error", "error": {"code": _code(e)}}, 2
    except KeyboardInterrupt:
        out, code = {"status": "interrupted"}, 130
    sys.stdout.write(canonical(out) + "\n")
    sys.stdout.flush()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
