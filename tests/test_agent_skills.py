from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = ROOT / ".agents" / "skills"
EXPECTED_SKILLS = {
    "artifact-production-qa",
    "clinical-software-safety",
    "research-protocol-publication",
    "robust-repo-change",
    "session-worklog",
}


def parse_frontmatter(text: str) -> dict[str, str]:
    normalized = text.replace("\r\n", "\n")
    if not normalized.startswith("---\n"):
        raise AssertionError("missing opening YAML delimiter")
    raw, separator, _body = normalized[4:].partition("\n---\n")
    if not separator:
        raise AssertionError("missing closing YAML delimiter")
    metadata: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            raise AssertionError(f"invalid frontmatter line: {line!r}")
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip()
    return metadata


class AgentSkillTests(unittest.TestCase):
    def test_expected_skill_catalog_is_present(self) -> None:
        discovered = {
            path.name
            for path in SKILLS_ROOT.iterdir()
            if path.is_dir() and (path / "SKILL.md").is_file()
        }
        self.assertEqual(EXPECTED_SKILLS, discovered)

    def test_each_skill_has_valid_activation_metadata(self) -> None:
        for name in sorted(EXPECTED_SKILLS):
            with self.subTest(skill=name):
                skill_file = SKILLS_ROOT / name / "SKILL.md"
                text = skill_file.read_text(encoding="utf-8")
                metadata = parse_frontmatter(text)
                self.assertEqual(name, metadata.get("name"))
                description = metadata.get("description", "")
                self.assertGreaterEqual(len(description), 40)
                self.assertRegex(text, re.compile(r"^## Purpose\s*$", re.MULTILINE))
                self.assertRegex(text, re.compile(r"^## Workflow\s*$", re.MULTILINE))
                self.assertTrue(text.endswith("\n"))

    def test_source_provenance_is_recorded(self) -> None:
        source = (SKILLS_ROOT / "SOURCE.md").read_text(encoding="utf-8")
        self.assertIn("kundakarlabp/dr-bhanu-prasad", source)
        self.assertIn("c92ac30e6c2e2c7998fd8ebf2669f90b117151a3", source)


if __name__ == "__main__":
    unittest.main()
