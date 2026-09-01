"""Validation of the scoring oracle against golden.yaml.

For each case: calls scoring.FUNZIONI[funzione](**kwargs) and compares each key of `atteso`
(also with a dotted path, e.g. metrics.AV) within tolerance. Correctness gate: the expected
values are verified by hand in RIFERIMENTO.md, not copied from the output.

Usage:  uv run python validate.py   (exit 0 if all PASS, 1 otherwise)
"""
import sys
from pathlib import Path

import yaml

import scoring

GOLDEN = Path(__file__).resolve().parent / "golden.yaml"


def _get(obj, path):
    for key in path.split("."):
        obj = obj[key]
    return obj


def _vicino(got, exp, tol_rel):
    if isinstance(exp, bool) or exp is None or isinstance(got, (str, type(None))):
        return got == exp
    if isinstance(exp, (int, float)):
        return abs(got - exp) <= max(tol_rel * abs(exp), 1e-9)
    return got == exp


def main() -> None:
    casi = yaml.safe_load(GOLDEN.read_text(encoding="utf-8"))["casi"]
    passed = 0
    for c in casi:
        nome, kwargs = c["funzione"], c.get("kwargs", {})
        tol = float(c.get("tol_rel", 1e-6))
        try:
            res = scoring.FUNZIONI[nome](**kwargs)
            errori = []
            for path, exp in c["atteso"].items():
                got = _get(res, path)
                if not _vicino(got, exp, tol):
                    errori.append(f"{path}: expected {exp}, got {got}")
        except Exception as e:  # a case that explodes is a failure, not a gate crash
            errori = [f"exception {type(e).__name__}: {e}"]
        ok = not errori
        passed += ok
        kw_str = ", ".join(f"{k}={v}" for k, v in kwargs.items())
        print(f"[{'PASS' if ok else 'FAIL'}] {nome}({kw_str[:70]})")
        for err in errori:
            print(f"        {err}")
    print(f"\n{passed}/{len(casi)} golden cases passed.")
    sys.exit(0 if passed == len(casi) else 1)


if __name__ == "__main__":
    main()
