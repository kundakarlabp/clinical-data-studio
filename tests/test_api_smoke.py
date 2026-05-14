import json
import tempfile
import threading
import unittest
from contextlib import closing
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
        self.original_uploads = server.UPLOADS
        self.original_db = server.DB_PATH
        server.DATA = Path(self.tmp.name)
        server.BACKUPS = server.DATA / "backups"
        server.UPLOADS = server.DATA / "uploads"
        server.DB_PATH = server.DATA / "smoke.sqlite3"
        server.migrate()
        with closing(server.db()) as conn, conn:
            conn.execute("UPDATE users SET must_change_password = 0 WHERE username = 'admin'")
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
        server.UPLOADS = self.original_uploads
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

    def response_headers(self, path):
        request = Request(f"{self.base_url}{path}")
        with urlopen(request, timeout=10) as response:
            return response.headers

    def test_health_login_summary_and_encrypted_backup(self):
        health = self.request_json("/api/health")
        self.assertTrue(health["ok"])
        healthz = self.request_json("/healthz")
        self.assertTrue(healthz["ok"])
        self.assertEqual(healthz["database_backend"], "sqlite")
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
        readiness = self.request_json(f"/api/studies/{study_id}/readiness", token=token)["readiness"]
        self.assertIn(readiness["status"], {"ready", "needs_review", "blocked"})
        self.assertIsInstance(readiness["score"], int)
        self.assertTrue(any(item["key"] == "backup" for item in readiness["items"]))
        self.assertTrue(readiness["next_actions"])

        backups = self.request_json(f"/api/studies/{study_id}/backups", token=token)["backups"]
        self.assertEqual(backups[0]["name"], backup["name"])

        restored = self.request_json(
            f"/api/studies/{study_id}/backups/{backup['name']}/restore",
            "POST",
            {"passphrase": "LongLocalPassphrase123"},
            token,
        )
        self.assertEqual(restored["restored"], backup["name"])

    def test_admin_status_and_system_backup(self):
        login = self.request_json("/api/login", "POST", {"username": "admin", "password": "admin123"})
        token = login["token"]
        status = self.request_json("/api/admin/status", token=token)
        self.assertTrue(status["health"]["ok"])
        self.assertEqual(status["settings"]["database_backend"], "sqlite")
        logs = self.request_json("/api/admin/logs", token=token)
        self.assertIn("lines", logs)
        backup = self.request_json("/api/admin/backup", "POST", {"passphrase": "LongLocalPassphrase123"}, token)["backup"]
        self.assertTrue(backup["encrypted"])
        self.assertTrue(backup["name"].startswith("system_"))

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

    def test_must_change_password_blocks_protected_endpoints_until_changed(self):
        with closing(server.db()) as conn, conn:
            conn.execute("UPDATE users SET must_change_password = 1 WHERE username = 'admin'")
        token = self.request_json("/api/login", "POST", {"username": "admin", "password": "admin123"})["token"]
        me = self.request_json("/api/me", token=token)
        self.assertEqual(me["user"]["must_change_password"], 1)
        with self.assertRaises(HTTPError) as blocked:
            self.request_json("/api/studies", token=token)
        self.assertEqual(blocked.exception.code, 403)
        self.assertIn("Password change required", blocked.exception.read().decode("utf-8"))
        blocked.exception.close()
        changed = self.request_json(
            "/api/password",
            "POST",
            {"current_password": "admin123", "new_password": "ChangedPassword123"},
            token,
        )
        self.assertTrue(changed["ok"])
        studies = self.request_json("/api/studies", token=token)["studies"]
        self.assertTrue(studies)

    def test_session_tokens_are_stored_as_digests_and_logout_removes_session(self):
        token = self.request_json("/api/login", "POST", {"username": "admin", "password": "admin123"})["token"]
        with closing(server.db()) as conn, conn:
            session = server.row(conn, "SELECT token FROM sessions LIMIT 1")
        self.assertIsNotNone(session)
        self.assertNotEqual(session["token"], token)
        self.assertEqual(session["token"], server.session_token_digest(token))
        logout = self.request_json("/api/logout", "POST", {}, token)
        self.assertTrue(logout["ok"])
        with closing(server.db()) as conn, conn:
            remaining = server.row(conn, "SELECT token FROM sessions WHERE token = ?", (server.session_token_digest(token),))
        self.assertIsNone(remaining)

    def test_security_headers_are_present(self):
        headers = self.response_headers("/api/health")
        self.assertIn("default-src 'self'", headers.get("Content-Security-Policy"))
        self.assertEqual(headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("Referrer-Policy"), "same-origin")

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

    def test_case_intake_groups_unstructured_cases_and_exports(self):
        token = self.request_json("/api/login", "POST", {"username": "admin", "password": "admin123"})["token"]
        study_id = self.request_json("/api/studies", token=token)["studies"][0]["id"]
        created = self.request_json(
            f"/api/studies/{study_id}/case-intake",
            "POST",
            {
                "case_uid": "CASE-RETRO-001",
                "title": "Influenza pneumonia with oseltamivir",
                "source_text": "A 42 year old female presented with fever. Diagnosis: influenza pneumonia. Treatment: oseltamivir. Outcome: improved.",
                "files": [{"name": "case-note.txt", "type": "text/plain", "size": 12, "data": "Y2FzZSBub3Rl"}],
            },
            token,
        )["case"]
        self.assertEqual(created["case_uid"], "CASE-RETRO-001")
        self.assertEqual(created["extracted"]["demographics"]["age"], "42")
        self.assertTrue(created["files"])
        self.assertEqual(created["files"][0]["sha256"], "627a6c2140448938132bb2441d164fb27a07312738406eed9a76bd31b61a0f8f")
        with closing(server.db()) as conn:
            file_record = server.row(conn, "SELECT * FROM case_files WHERE id = ?", (created["files"][0]["id"],))
            self.assertTrue(file_record["stored_filename"])
            self.assertFalse(file_record["data_base64"])
            self.assertTrue((server.UPLOADS / "studies" / str(study_id) / "cases" / str(created["id"]) / file_record["stored_filename"]).exists())
        _, file_type, file_body = self.request_raw(f"/api/studies/{study_id}/case-intake/{created['id']}/files/{created['files'][0]['id']}", token=token)
        self.assertIn("text/plain", file_type)
        self.assertEqual(file_body, b"case note")
        review = self.request_json(
            f"/api/studies/{study_id}/case-intake/{created['id']}/ai-review",
            "POST",
            {"question": "Can this become a case report?"},
            token,
        )["review"]
        self.assertEqual(review["mode"], "local")
        self.assertIn("publication_guidance", review["response"])
        self.assertTrue(review["response"]["adaptive_crf_suggestions"])
        library = self.request_json(f"/api/studies/{study_id}/case-intake", token=token)
        self.assertEqual(library["series"]["case_count"], 1)
        self.assertTrue(library["series"]["adaptive_fields"])
        saved_case = next(item for item in library["cases"] if item["case_uid"] == "CASE-RETRO-001")
        self.assertTrue(saved_case["latest_ai_review"])
        self.assertTrue(library["series"]["groups"])
        _, csv_type, csv_body = self.request_raw(f"/api/studies/{study_id}/case-intake/export", token=token)
        self.assertIn("text/csv", csv_type)
        self.assertIn(b"CASE-RETRO-001", csv_body)

        academic = self.request_json(f"/api/studies/{study_id}/academic", token=token)["academic"]
        self.assertEqual(academic["metrics"]["case_count"], 1)
        self.assertTrue(academic["opportunities"])
        self.assertIn("cv_markdown", academic)
        cv_item = self.request_json(
            f"/api/studies/{study_id}/academic/cv-items",
            "POST",
            {
                "item_type": "case_report",
                "title": "Influenza pneumonia case report",
                "role": "First author",
                "status": "drafting",
                "linked_case_id": created["id"],
                "notes": "Prepare CARE checklist.",
            },
            token,
        )["cv_item"]
        self.assertEqual(cv_item["title"], "Influenza pneumonia case report")
        updated_academic = self.request_json(f"/api/studies/{study_id}/academic", token=token)["academic"]
        self.assertEqual(updated_academic["metrics"]["cv_item_count"], 1)
        _, md_type, md_body = self.request_raw(f"/api/studies/{study_id}/academic/export?format=md", token=token)
        self.assertIn("text/markdown", md_type)
        self.assertIn(b"Influenza pneumonia case report", md_body)

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

    def test_rbac_and_api_token_scope_enforcement(self):
        admin_login = self.request_json("/api/login", "POST", {"username": "admin", "password": "admin123"})
        admin_token = admin_login["token"]
        study_id = self.request_json("/api/studies", token=admin_token)["studies"][0]["id"]
        data_user = self.request_json(
            "/api/users",
            "POST",
            {"username": "entry.user", "display_name": "Entry User", "password": "Temporary12345", "role": "data_entry"},
            admin_token,
        )["user"]
        analyst_user = self.request_json(
            "/api/users",
            "POST",
            {"username": "analyst.user", "display_name": "Analyst User", "password": "Temporary12345", "role": "analyst"},
            admin_token,
        )["user"]
        self.request_json(f"/api/studies/{study_id}/memberships", "POST", {"user_id": data_user["id"], "role": "data_entry", "active": True}, admin_token)
        self.request_json(f"/api/studies/{study_id}/memberships", "POST", {"user_id": analyst_user["id"], "role": "analyst", "active": True}, admin_token)

        entry_token = self.request_json("/api/login", "POST", {"username": "entry.user", "password": "Temporary12345"})["token"]
        created = self.request_json(
            f"/api/studies/{study_id}/participants",
            "POST",
            {"study_uid": "RBAC001", "initials": "RB", "status": "enrolled"},
            entry_token,
        )["participant"]
        self.assertEqual(created["study_uid"], "RBAC001")
        form_id = self.request_json(f"/api/studies/{study_id}/forms", token=entry_token)["forms"][0]["id"]
        self.request_json(
            f"/api/studies/{study_id}/entries",
            "POST",
            {
                "participant_id": created["id"],
                "form_id": form_id,
                "status": "complete",
                "data": {"age": "44", "sex": "Male", "consent_date": "2026-05-07", "diagnosis": "RBAC test"},
            },
            entry_token,
        )
        with self.assertRaises(HTTPError) as export_denied:
            self.request_raw(f"/api/studies/{study_id}/export", token=entry_token)
        self.assertEqual(export_denied.exception.code, 403)
        export_denied.exception.close()

        analyst_token = self.request_json("/api/login", "POST", {"username": "analyst.user", "password": "Temporary12345"})["token"]
        with self.assertRaises(HTTPError) as edit_denied:
            self.request_json(f"/api/studies/{study_id}/participants", "POST", {"study_uid": "RBAC002"}, analyst_token)
        self.assertEqual(edit_denied.exception.code, 403)
        edit_denied.exception.close()
        status, content_type, body = self.request_raw(f"/api/studies/{study_id}/export", token=analyst_token)
        self.assertEqual(status, 200)
        self.assertIn("text/csv", content_type)
        self.assertIn(b"EXP00001", body)

        scoped_token = self.request_json(
            f"/api/studies/{study_id}/api-tokens",
            "POST",
            {"user_id": admin_login["user"]["id"], "label": "metadata only", "scopes": ["metadata:read"]},
            admin_token,
        )["token"]
        metadata = self.request_json(f"/api/redcap?token={scoped_token}&content=metadata&format=json")
        self.assertTrue(metadata)
        with self.assertRaises(HTTPError) as scoped_denied:
            self.request_json(f"/api/redcap?token={scoped_token}&content=record&format=json")
        self.assertEqual(scoped_denied.exception.code, 403)
        scoped_denied.exception.close()


if __name__ == "__main__":
    unittest.main()
