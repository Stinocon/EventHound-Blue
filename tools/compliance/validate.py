"""Validation of the compliance resolver against golden.yaml.

For each case, compares the set of applicable obligation ids (and, if indicated, the most
urgent deadline). Correctness gate for the matching LOGIC. Usage: uv run python validate.py
"""
import sys
from pathlib import Path

import yaml

import compliance

GOLDEN = Path(__file__).resolve().parent / "golden.yaml"


def main() -> None:
    casi = yaml.safe_load(GOLDEN.read_text(encoding="utf-8"))["casi"]
    passed = 0
    for c in casi:
        errori = []
        try:
            res = compliance.summary(c["incident"])
            got_ids = sorted(o["id"] for o in res["obligations"])
            exp_ids = sorted(c["expect_ids"])
            if got_ids != exp_ids:
                errori.append(f"ids: expected {exp_ids}, got {got_ids}")
            if "most_urgent_id" in c:
                mu = (res["most_urgent"] or {}).get("id")
                if mu != c["most_urgent_id"]:
                    errori.append(f"most_urgent: expected {c['most_urgent_id']}, got {mu}")
        except Exception as e:
            errori = [f"exception {type(e).__name__}: {e}"]
        ok = not errori
        passed += ok
        print(f"[{'PASS' if ok else 'FAIL'}] {c['nome']}")
        for err in errori:
            print(f"        {err}")
    print(f"\n{passed}/{len(casi)} golden cases passed.")
    sys.exit(0 if passed == len(casi) else 1)


if __name__ == "__main__":
    main()
