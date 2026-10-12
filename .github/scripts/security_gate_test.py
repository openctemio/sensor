#!/usr/bin/env python3
"""Checks this repository's security gate configuration. The gate script
itself is a copy of openctemio/openctem's .github/scripts/security_gate.py and
is tested there. Run: python3 .github/scripts/security_gate_test.py"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import security_gate as sg  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG = sg.load_config((ROOT / ".github/security-paths.yml").read_text())


class ConfigTest(unittest.TestCase):
    def test_parses_with_ackers(self):
        self.assertIn("0xmanhnv", CONFIG["ackers"])
        self.assertTrue(sg.categories(CONFIG))

    def test_every_pattern_matches_a_tracked_file(self):
        # A typo in the list silently exempts a path; fail instead.
        files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
        for cat, globs in CONFIG.items():
            if cat == "ackers":
                continue
            for g in globs:
                rx = sg.glob_to_regex(g)
                self.assertTrue(any(rx.match(f) for f in files), f"{cat}: {g} matches no tracked file")

    def test_codeowners_in_sync(self):
        text = (ROOT / ".github/CODEOWNERS").read_text()
        self.assertEqual(sg.splice_codeowners(text, sg.codeowners_block(CONFIG)), text,
                         "run: python3 .github/scripts/security_gate.py codeowners --write")

    def test_gate_files_are_sensitive(self):
        for name in (".github/workflows/security-gate.yml", ".github/security-paths.yml",
                     ".github/scripts/security_gate.py", ".github/CODEOWNERS"):
            self.assertTrue(sg.classify([sg.ChangedFile(name)], CONFIG), name)

    def test_added_test_is_not_sensitive(self):
        f = sg.ChangedFile("pkg/x/new_test.go", "added", 0, "@@ -0,0 +1 @@\n+x")
        self.assertEqual(sg.classify([f], CONFIG), {})


if __name__ == "__main__":
    unittest.main()
