from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class FrontendStaticTests(unittest.TestCase):
    def test_mobile_pwa_shell_is_present(self):
        index = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        css = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")
        manifest = (ROOT / "static" / "manifest.json").read_text(encoding="utf-8")
        self.assertIn('name="viewport"', index)
        self.assertIn('rel="manifest"', index)
        self.assertIn("@media (max-width: 860px)", css)
        self.assertIn('"display"', manifest)

    def test_frontend_uses_new_hardening_endpoints(self):
        app_js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("/assist/summary", app_js)
        self.assertIn("encrypted-backup-form", app_js)
        self.assertIn("Create Encrypted Archive", app_js)


if __name__ == "__main__":
    unittest.main()
