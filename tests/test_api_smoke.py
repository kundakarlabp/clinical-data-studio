import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server


class ApiSmokeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_data = server.DATA
        self.original_backups = server.BACKUPS
        self.original_db = server.DB_PATH
        server.DATA = Path(self.tmp.name)
        server.BACKUPS = server.DATA / "backups"
        server.DB_PATH = server.DATA / "smoke.sqlite3"
        server.migrate()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.App)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        server.DATA = self.original_data
        server.BACKUPS = self.original_backups
        server.DB_PATH = self.original_db
        self.tmp.cleanup()

    def request_json(self, path, method="GET", payload=None, token=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = Request(f"{self.base_url}{path}", data=body, headers=headers, method=method)
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_health_login_summary_and_encrypted_backup(self):
        health = self.request_json("/api/health")
        self.assertTrue(health["ok"])

        login = self.request_json("/api/login", "POST", {"username": "admin", "password": "admin123"})
        token = login["token"]
        studies = self.request_json("/api/studies", token=token)["studies"]
        study_id = studies[0]["id"]

        summary = self.request_json(f"/api/studies/{study_id}/assist/summary", token=token)["summary"]
        self.assertIn("participant_count", summary)
        self.assertTrue(summary["next_steps"])

        backup = self.request_json(f"/api/studies/{study_id}/backups", "POST", {"passphrase": "LongLocalPassphrase123"}, token)["backup"]
        self.assertTrue(backup["encrypted"])
        self.assertTrue(backup["name"].endswith(".cdsenc"))

        backups = self.request_json(f"/api/studies/{study_id}/backups", token=token)["backups"]
        self.assertEqual(backups[0]["name"], backup["name"])

        restored = self.request_json(
            f"/api/studies/{study_id}/backups/{backup['name']}/restore",
            "POST",
            {"passphrase": "LongLocalPassphrase123"},
            token,
        )
        self.assertEqual(restored["restored"], backup["name"])

    def test_short_archive_passphrase_is_rejected(self):
        token = self.request_json("/api/login", "POST", {"username": "admin", "password": "admin123"})["token"]
        study_id = self.request_json("/api/studies", token=token)["studies"][0]["id"]
        with self.assertRaises(HTTPError) as context:
            self.request_json(f"/api/studies/{study_id}/backups", "POST", {"passphrase": "short"}, token)
        self.assertEqual(context.exception.code, 400)
        context.exception.close()

    def test_encrypted_archive_round_trip(self):
        plain = b"sqlite data bytes"
        archive = server.encrypted_archive_bytes(plain, "LongLocalPassphrase123")
        self.assertEqual(server.decrypted_archive_bytes(archive, "LongLocalPassphrase123"), plain)
        with self.assertRaises(ValueError):
            server.decrypted_archive_bytes(archive, "WrongLocalPassphrase123")

    def test_first_run_setup_and_login_lockout(self):
        self.assertTrue(self.request_json("/api/setup")["required"])
        result = self.request_json(
            "/api/setup",
            "POST",
            {
                "username": "research.admin",
                "display_name": "Research Admin",
                "password": "VeryStrongAdmin123",
                "confirm_password": "VeryStrongAdmin123",
            },
        )
        self.assertTrue(result["ok"])
        self.assertFalse(self.request_json("/api/setup")["required"])
        with self.assertRaises(HTTPError) as old_default:
            self.request_json("/api/login", "POST", {"username": "admin", "password": "admin123"})
        old_default.exception.close()
        login = self.request_json("/api/login", "POST", {"username": "research.admin", "password": "VeryStrongAdmin123"})
        self.assertEqual(login["user"]["username"], "research.admin")

        for _ in range(5):
            with self.assertRaises(HTTPError) as failed_login:
                self.request_json("/api/login", "POST", {"username": "research.admin", "password": "wrong"})
            failed_login.exception.close()
        with self.assertRaises(HTTPError) as context:
            self.request_json("/api/login", "POST", {"username": "research.admin", "password": "VeryStrongAdmin123"})
        self.assertEqual(context.exception.code, 423)
        context.exception.close()

    def test_record_import_and_entry_history(self):
        token = self.request_json("/api/login", "POST", {"username": "admin", "password": "admin123"})["token"]
        study_id = self.request_json("/api/studies", token=token)["studies"][0]["id"]
        csv_text = "\n".join(
            [
                "study_uid,initials,participant_status,event_code,form_code,entry_status,repeat_instance,demographics__age,demographics__sex,demographics__consent_date,demographics__diagnosis",
                "P900,ZZ,enrolled,baseline,demographics,complete,1,45,Female,2026-05-01,Registry",
            ]
        )
        result = self.request_json(f"/api/studies/{study_id}/records/import", "POST", {"csv": csv_text}, token)["imported"]
        self.assertEqual(result["entries_created"], 1)
        entries = self.request_json(f"/api/studies/{study_id}/entries", token=token)["entries"]
        entry = next(item for item in entries if item["study_uid"] == "P900")
        history = self.request_json(f"/api/studies/{study_id}/entries/{entry['id']}/history", token=token)
        self.assertTrue(history["history"])

    def test_public_survey_with_consent_and_file_upload(self):
        token = self.request_json("/api/login", "POST", {"username": "admin", "password": "admin123"})["token"]
        study_id = self.request_json("/api/studies", token=token)["studies"][0]["id"]
        forms = self.request_json(f"/api/studies/{study_id}/forms", token=token)["forms"]
        form_id = forms[0]["id"]
        schema = forms[0]["schema"]
        schema["fields"].append({"code": "attachment", "label": "Attachment", "type": "file", "required": False})
        self.request_json(
            f"/api/studies/{study_id}/forms/{form_id}",
            "PATCH",
            {"name": forms[0]["name"], "code": forms[0]["code"], "schema": schema},
            token,
        )
        survey = self.request_json(
            f"/api/studies/{study_id}/surveys",
            "POST",
            {
                "title": "Public Intake",
                "form_id": form_id,
                "consent_required": True,
                "consent_text": "I agree to submit this research form.",
            },
            token,
        )["survey"]

        public = self.request_json(f"/api/public/surveys/{survey['token']}")["survey"]
        self.assertTrue(public["consent_required"])
        submit = self.request_json(
            f"/api/public/surveys/{survey['token']}",
            "POST",
            {
                "participant": {"study_uid": "PUB001", "initials": "PB"},
                "data": {
                    "age": "33",
                    "sex": "Male",
                    "consent_date": "2026-05-05",
                    "diagnosis": "Registry",
                    "attachment": {"name": "note.txt", "type": "text/plain", "data": "SGVsbG8="},
                },
                "consent": {"signer_name": "Public User", "signature_text": "Public User"},
            },
        )
        self.assertTrue(submit["ok"])
        entries = self.request_json(f"/api/studies/{study_id}/entries", token=token)["entries"]
        entry = next(item for item in entries if item["study_uid"] == "PUB001")
        self.assertEqual(entry["data"]["attachment"]["name"], "note.txt")

    def test_survey_invitation_tracking_and_validation_evidence(self):
        token = self.request_json("/api/login", "POST", {"username": "admin", "password": "admin123"})["token"]
        study_id = self.request_json("/api/studies", token=token)["studies"][0]["id"]
        form_id = self.request_json(f"/api/studies/{study_id}/forms", token=token)["forms"][0]["id"]
        survey = self.request_json(f"/api/studies/{study_id}/surveys", "POST", {"title": "Invite Survey", "form_id": form_id}, token)["survey"]
        invitation = self.request_json(
            f"/api/studies/{study_id}/invitations",
            "POST",
            {"survey_link_id": survey["id"], "contact": "coordinator-call"},
            token,
        )["invitation"]
        sent = self.request_json(f"/api/studies/{study_id}/invitations/{invitation['id']}", "PATCH", {"action": "mark_sent"}, token)["invitation"]
        self.assertEqual(sent["status"], "sent")
        evidence = self.request_json(f"/api/studies/{study_id}/validation", token=token)
        self.assertGreaterEqual(evidence["counts"]["survey_invitations"], 1)
        self.assertTrue(evidence["checks"])


if __name__ == "__main__":
    unittest.main()
