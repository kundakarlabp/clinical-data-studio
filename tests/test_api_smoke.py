import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
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

    def request_raw(self, path, method="GET", payload=None, token=None, content_type="application/json"):
        if isinstance(payload, dict) and content_type == "application/x-www-form-urlencoded":
            body = urlencode(payload).encode("utf-8")
        else:
            body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": content_type}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = Request(f"{self.base_url}{path}", data=body, headers=headers, method=method)
        with urlopen(request, timeout=10) as response:
            return response.status, response.headers.get("content-type", ""), response.read()

    def test_health_login_summary_and_encrypted_backup(self):
        health = self.request_json("/api/health")
        self.assertTrue(health["ok"])
        self.assertIn("data_folder_encrypted", health["data_protection"])
        self.assertFalse(health["ai"]["external_ai_enabled"])

        login = self.request_json("/api/login", "POST", {"username": "admin", "password": "admin123"})
        token = login["token"]
        studies = self.request_json("/api/studies", token=token)["studies"]
        study_id = studies[0]["id"]

        summary = self.request_json(f"/api/studies/{study_id}/assist/summary", token=token)["summary"]
        self.assertIn("participant_count", summary)
        self.assertTrue(summary["next_steps"])
        draft = self.request_json(
            "/api/assist/crf",
            "POST",
            {"text": "Age\nVisit date\nAny adverse event?"},
            token,
        )
        self.assertEqual(draft["assistant"]["mode"], "local")
        self.assertEqual(draft["schema"]["fields"][0]["type"], "number")

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
        self.assertIn("data_protection", evidence)
        self.assertTrue(evidence["checks"])
        _, package_type, package_body = self.request_raw(f"/api/studies/{study_id}/validation-package", token=token)
        self.assertIn("application/zip", package_type)
        self.assertIn(b"validation_evidence.json", package_body)

    def test_api_tokens_redcap_endpoint_exports_and_randomization(self):
        login = self.request_json("/api/login", "POST", {"username": "admin", "password": "admin123"})
        token = login["token"]
        study_id = self.request_json("/api/studies", token=token)["studies"][0]["id"]
        api_token = self.request_json(
            f"/api/studies/{study_id}/api-tokens",
            "POST",
            {"user_id": login["user"]["id"], "label": "test token"},
            token,
        )["token"]

        metadata = self.request_json(f"/api/redcap?token={api_token}&content=metadata&format=json")
        self.assertTrue(metadata)
        project = self.request_json(f"/api/redcap?token={api_token}&content=project&format=json")
        self.assertEqual(project["id"], study_id)
        version = self.request_json(f"/api/redcap?token={api_token}&content=version&format=json")
        self.assertEqual(version["application"], "Clinical Data Studio")
        arms = self.request_json(f"/api/redcap?token={api_token}&content=arm&format=json")
        self.assertEqual(arms[0]["arm_num"], 1)
        users = self.request_json(f"/api/redcap?token={api_token}&content=user&format=json")
        self.assertEqual(users[0]["username"], "admin")
        self.assertEqual(users[0]["manage_users"], "1")
        group = self.request_json(
            f"/api/studies/{study_id}/groups",
            "POST",
            {"name": "Site A", "code": "site_a"},
            token,
        )["group"]
        dags = self.request_json(f"/api/redcap?token={api_token}&content=dag&format=json")
        self.assertEqual(dags[0]["unique_group_name"], group["code"])
        status, content_type, csv_body = self.request_raw(
            "/api/redcap",
            "POST",
            {"token": api_token, "content": "record", "format": "csv"},
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(status, 200)
        self.assertIn("text/csv", content_type)
        self.assertIn(b"study_uid", csv_body)

        _, odm_type, odm_body = self.request_raw(f"/api/studies/{study_id}/odm", token=token)
        self.assertIn("application/xml", odm_type)
        self.assertIn(b"<ODM", odm_body)
        _, zip_type, zip_body = self.request_raw(f"/api/studies/{study_id}/stats-package?type=r", token=token)
        self.assertIn("application/zip", zip_type)
        self.assertGreater(len(zip_body), 100)

        participant = self.request_json(
            f"/api/studies/{study_id}/participants",
            "POST",
            {"study_uid": "RAND001", "initials": "RA", "status": "enrolled"},
            token,
        )["participant"]
        random_list = self.request_json(
            f"/api/studies/{study_id}/randomization",
            "POST",
            {"name": "1 to 1", "arms": "Control,Treatment"},
            token,
        )["list"]
        allocation = self.request_json(
            f"/api/studies/{study_id}/randomization/{random_list['id']}/allocate",
            "POST",
            {"participant_id": participant["id"]},
            token,
        )["allocation"]
        self.assertIn(allocation["arm"], {"Control", "Treatment"})
        audit_rows = self.request_json(f"/api/studies/{study_id}/audit", token=token)["audit"]
        self.assertTrue(any(item["action"] == "api_request" for item in audit_rows))
        _, audit_type, audit_body = self.request_raw(f"/api/studies/{study_id}/audit-export", token=token)
        self.assertIn("text/csv", audit_type)
        self.assertIn(b"api_request", audit_body)

        token_record = self.request_json(f"/api/studies/{study_id}/api-tokens", token=token)["tokens"][0]
        revoked = self.request_json(
            f"/api/studies/{study_id}/api-tokens/{token_record['id']}",
            "PATCH",
            {"active": False},
            token,
        )["token"]
        self.assertFalse(revoked["active"])
        try:
            self.request_json(f"/api/redcap?token={api_token}&content=project&format=json")
        except HTTPError as denied:
            self.assertEqual(denied.code, 401)
            denied.close()
        else:
            self.fail("Revoked token should be rejected")


if __name__ == "__main__":
    unittest.main()
