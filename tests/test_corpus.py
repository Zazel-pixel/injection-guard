"""The measured bar: detection and false alarms on the committed corpus.

These thresholds are the numbers of 2026-11-07. A change to the patterns that
lowers detection or raises false alarms fails here. Moving a threshold is a
decision to write in the commit message, with evaluate.py output before and
after, not a way to get back to green.

    python3 -m unittest discover -s tests
"""
import importlib.util
import os
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
GUARD = Path(os.environ.get("INJECTION_GUARD_PATH") or ROOT / "injection_guard.py")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Corpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        evaluate = load("evaluate", ROOT / "evaluate.py")
        res = evaluate.evaluate(evaluate.load_guard(GUARD), evaluate.load_corpus())
        cls.groups = res["groups"]
        cls.benign = [a["id"] for a in res["benign_alerts"]]

    def rate(self, key):
        g = self.groups[key]
        return g["alerted"] / g["docs"]

    def test_explicit_injections_in_tool_outputs(self):
        self.assertEqual(self.rate("attack:injecagent/enhanced"), 1.0)

    def test_held_out_lakera_prompts(self):
        # 0.46 -> 0.45 on 2026-11-07, on purpose: requiring a determiner in
        # credential-bait ("enter your password", not "Enter password") ended
        # four kinds of real false alarms and cost one held-out prompt (52 -> 51
        # of 112), while train and validation went up.
        self.assertGreaterEqual(self.rate("attack:lakera/test"), 0.45)

    def test_benign_tool_outputs_and_prompts(self):
        for key in ("benign:injecagent/clean", "benign:deepset/en/train",
                    "benign:deepset/en/test", "benign:self"):
            with self.subTest(key):
                self.assertEqual(self.groups[key]["alerted"], 0)

    def test_known_false_alarms_do_not_grow(self):
        # Four regressions are still flagged, on purpose: an unquoted command
        # that reads a secret file (twice), a README that tells the reader to
        # run a script before going on, and an "### Instruction:" heading. See
        # corpus/regressions.jsonl and the README.
        self.assertLessEqual(len(self.benign), 4, self.benign)


if __name__ == "__main__":
    unittest.main()
