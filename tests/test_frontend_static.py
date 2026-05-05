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
        self.assertIn("First Run Setup", app_js)
        self.assertIn("/records/import", app_js)
        self.assertIn("/history", app_js)
        self.assertIn("/surveys", app_js)
        self.assertIn("/invitations", app_js)
        self.assertIn("/validation", app_js)
        self.assertIn("/api-tokens", app_js)
        self.assertIn("/randomization", app_js)
        self.assertIn("/odm", app_js)
        self.assertIn("/stats-package", app_js)
        self.assertIn("type=\"file\"", app_js)

    def test_public_survey_shell_is_present(self):
        survey_html = (ROOT / "static" / "survey.html").read_text(encoding="utf-8")
        survey_js = (ROOT / "static" / "survey.js").read_text(encoding="utf-8")
        self.assertIn('name="viewport"', survey_html)
        self.assertIn("/api/public/surveys/", survey_js)
        self.assertIn("Consent", survey_js)
        self.assertIn("invitationToken", survey_js)

    def test_browser_smoke_script_is_present(self):
        smoke = (ROOT / "tests" / "browser_smoke.ps1").read_text(encoding="utf-8")
        self.assertIn("Pixel 7", smoke)
        self.assertIn("Browser smoke passed", smoke)


if __name__ == "__main__":
    unittest.main()
