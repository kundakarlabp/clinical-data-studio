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

HTTP_TIMEOUT = 10


class RecruitmentAndAiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.original_data = server.DATA
        self.original_backups = server.BACKUPS
        self.original_uploads = server.UPLOADS
        self.original_db = server.DB_PATH
        self.original_backend = server.DATABASE_BACKEND
        server.DATA = Path(self.tmp.name)
        server.BACKUPS = server.DATA / "backups"
        server.UPLOADS = server.DATA / "uploads"
        server.DB_PATH = server.DATA / "test_recruitment_ai.sqlite3"
        server.DATABASE_BACKEND = "sqlite"
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
        server.DATABASE_BACKEND = self.original_backend
        self.tmp.cleanup()

    def request_json(self, path, method="GET", payload=None, token=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        headers.update(self.auth_headers(token, method))
        request = Request(f"{self.base_url}{path}", data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=HTTP_TIMEOUT) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as e:
            print("HTTP ERROR RESPONSE BODY:", e.read().decode("utf-8"))
            raise e

    def auth_headers(self, token, method="GET"):
        if not token:
            return {}
        if isinstance(token, dict):
            return dict(token)
        if isinstance(token, str) and "cds_session=" in token:
            headers = {"Cookie": token}
            if method in {"POST", "PATCH", "DELETE"}:
                csrf_request = Request(f"{self.base_url}/api/csrf", headers={"Cookie": token})
                with urlopen(csrf_request, timeout=HTTP_TIMEOUT) as response:
                    csrf = json.loads(response.read().decode("utf-8"))["csrf_token"]
                headers["X-CSRF-Token"] = csrf
                headers["Origin"] = self.base_url
            return headers
        return {"Authorization": f"Bearer {token}"}

    def login_session(self, username="admin", password="admin123"):
        body = json.dumps({"username": username, "password": password}).encode("utf-8")
        request = Request(f"{self.base_url}/api/login", data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request, timeout=HTTP_TIMEOUT) as response:
            headers = response.headers
            cookie = headers.get("Set-Cookie")
            self.assertIsNotNone(cookie)
            return cookie

    def test_recruitment_and_ai_workflow(self):
        token = self.login_session()

        # 1. Fetch study and update eligibility criteria
        studies = self.request_json("/api/studies", token=token)["studies"]
        self.assertTrue(len(studies) > 0)
        study_id = studies[0]["id"]

        criteria = {
            "inclusion": [
                {"id": "INC01", "label": "Age >= 18"},
                {"id": "INC02", "label": "Informed consent obtained"}
            ],
            "exclusion": [
                {"id": "EXC01", "label": "History of cardiovascular disease"}
            ]
        }

        updated_study = self.request_json(
            f"/api/studies/{study_id}",
            "PATCH",
            {"eligibility_criteria": criteria},
            token=token
        )["study"]
        self.assertEqual(updated_study["eligibility_criteria"]["inclusion"][0]["id"], "INC01")

        # 2. Add a screening participant with a completed checklist
        participant = self.request_json(
            f"/api/studies/{study_id}/participants",
            "POST",
            {
                "study_uid": "SCREEN-101",
                "initials": "JD",
                "status": "screening",
                "recruitment_source": "Clinic A",
                "screening_date": 1782000000,
                "consent_status": "obtained",
                "consent_date": 1782000000,
                "consent_version": "v1.0",
                "eligibility_checklist": {
                    "INC01": "yes",
                    "INC02": "yes",
                    "EXC01": "no"
                },
                "screening_notes": "Healthy male, looks eligible."
            },
            token=token
        )["participant"]
        self.assertEqual(participant["study_uid"], "SCREEN-101")
        self.assertEqual(participant["eligibility_evaluation"]["eligible"], True)

        # 3. Add an ineligible participant to test screen failures
        ineligible_pt = self.request_json(
            f"/api/studies/{study_id}/participants",
            "POST",
            {
                "study_uid": "SCREEN-102",
                "initials": "MS",
                "status": "screening",
                "recruitment_source": "Web",
                "screening_date": 1782000000,
                "consent_status": "pending",
                "eligibility_checklist": {
                    "INC01": "no",  # Fails inclusion
                    "INC02": "yes",
                    "EXC01": "yes"  # Violates exclusion
                }
            },
            token=token
        )["participant"]
        self.assertEqual(ineligible_pt["eligibility_evaluation"]["eligible"], False)

        # 4. Trigger participant rule-check to generate eligibility check draft
        rule_check_res = self.request_json(
            f"/api/studies/{study_id}/participants/{participant['id']}/rule-check",
            "POST",
            {},
            token=token
        )
        self.assertTrue(rule_check_res["ok"])
        self.assertTrue(rule_check_res["eligible"])
        self.assertEqual(rule_check_res["suggested_status"], "enrolled")

        # 5. Fetch drafts queue and verify the eligibility_check is present
        drafts_payload = self.request_json(f"/api/studies/{study_id}/ai-drafts", token=token)
        drafts = drafts_payload["drafts"]
        audit_log = drafts_payload["audit_log"]

        self.assertTrue(len(drafts) > 0)
        eligibility_draft = next(d for d in drafts if d["draft_type"] == "eligibility_check")
        self.assertEqual(eligibility_draft["entity_id"], participant["id"])
        self.assertEqual(eligibility_draft["draft_json"]["suggested_status"], "enrolled")

        # Check audit trail logs rule check
        self.assertTrue(any(item["action"] == "rule_check" for item in audit_log))

        # 6. Approve the eligibility draft and verify participant status updates
        review_res = self.request_json(
            f"/api/studies/{study_id}/ai-drafts/{eligibility_draft['id']}/review",
            "POST",
            {"action": "approve"},
            token=token
        )
        self.assertTrue(review_res["ok"])

        # Fetch participant and check updated status
        participants = self.request_json(f"/api/studies/{study_id}/participants", token=token)["participants"]
        jd_pt = next(p for p in participants if p["id"] == participant["id"])
        self.assertEqual(jd_pt["status"], "enrolled")

        # 7. Create CRF Form with age required=True
        form = self.request_json(
            f"/api/studies/{study_id}/forms",
            "POST",
            {
                "name": "Demographics Form",
                "code": "demog",
                "schema": {
                    "fields": [
                        {"code": "age", "label": "Age", "type": "number", "required": True}
                    ]
                }
            },
            token=token
        )["form"]

        # Save an entry with valid age: 25
        entry = self.request_json(
            f"/api/studies/{study_id}/entries",
            "POST",
            {
                "participant_id": participant["id"],
                "form_id": form["id"],
                "event_name": "Baseline",
                "repeat_instance": 1,
                "status": "complete",
                "data": {
                    "age": "25"
                }
            },
            token=token
        )["entry"]

        # Directly update the entry data to be empty in DB (bypassing validation on save)
        with closing(server.db()) as conn, conn:
            conn.execute("UPDATE entries SET data_json = '{\"age\": \"\"}' WHERE id = ?", (entry["id"],))

        # 8. Test ChatGPT prompt export for CRF Forms
        export_form_res = self.request_json(
            f"/api/studies/{study_id}/forms/{form['id']}/export-chatgpt",
            "POST",
            {},
            token=token
        )
        self.assertIn("CRF SCHEMA", export_form_res["prompt"])

        # 9. Test Manual ChatGPT response Import with JSON true (lowercase) and adding gender field
        chatgpt_response_text = """
        Here is the optimized schema:
        ```json
        {
          "schema": {
            "fields": [
              {"code": "age", "label": "Subject Age", "type": "number", "required": true},
              {"code": "gender", "label": "Subject Gender", "type": "select", "options": ["Male", "Female", "Other"]}
            ]
          }
        }
        ```
        """
        import_res = self.request_json(
            f"/api/studies/{study_id}/import-ai-draft",
            "POST",
            {
                "entity_type": "form",
                "entity_id": form["id"],
                "draft_type": "crf_optimization",
                "text": chatgpt_response_text
            },
            token=token
        )
        self.assertEqual(import_res["count"], 1)

        # Retrieve drafts to get the crf_optimization draft
        drafts_payload = self.request_json(f"/api/studies/{study_id}/ai-drafts", token=token)
        optimization_draft = next(d for d in drafts_payload["drafts"] if d["draft_type"] == "crf_optimization")

        # Approve optimization draft
        review_opt_res = self.request_json(
            f"/api/studies/{study_id}/ai-drafts/{optimization_draft['id']}/review",
            "POST",
            {"action": "approve"},
            token=token
        )
        self.assertTrue(review_opt_res["ok"])

        # Fetch form and verify fields updated
        updated_forms = self.request_json(f"/api/studies/{study_id}/forms", token=token)["forms"]
        jd_form = next(f for f in updated_forms if f["id"] == form["id"])
        self.assertEqual(len(jd_form["schema"]["fields"]), 2)
        self.assertEqual(jd_form["schema"]["fields"][1]["code"], "gender")

        # 10. Test Case Intake Prompt Export with local de-identification
        case_intake = self.request_json(
            f"/api/studies/{study_id}/case-intake",
            "POST",
            {
                "case_uid": "CASE-101",
                "title": "Severe Flu Case",
                "status": "draft",
                "source_text": "Patient name: John Doe\nPhone number: +1-555-019-9999\nDetails: presented with high fever."
            },
            token=token
        )["case"]

        export_case_res = self.request_json(
            f"/api/studies/{study_id}/case-intake/{case_intake['id']}/export-chatgpt",
            "POST",
            {},
            token=token
        )
        self.assertIn("INCLUSION CRITERIA", export_case_res["prompt"])
        self.assertNotIn("John Doe", export_case_res["prompt"])
        self.assertNotIn("555-019-9999", export_case_res["prompt"])

        # 11. Run consistency rule check on entry now that the entry contains invalid (empty) age in the database
        entry_rule_check_res = self.request_json(
            f"/api/studies/{study_id}/entries/{entry['id']}/rule-check",
            "POST",
            {},
            token=token
        )
        self.assertTrue(entry_rule_check_res["ok"])
        self.assertEqual(entry_rule_check_res["issues_found"], 1)

        # Retrieve drafts and verify query_draft is present
        drafts_payload = self.request_json(f"/api/studies/{study_id}/ai-drafts", token=token)
        query_draft = next(d for d in drafts_payload["drafts"] if d["draft_type"] == "query_draft")
        self.assertEqual(query_draft["draft_json"]["field_code"], "age")

        # Approve query draft
        review_query_res = self.request_json(
            f"/api/studies/{study_id}/ai-drafts/{query_draft['id']}/review",
            "POST",
            {"action": "approve"},
            token=token
        )
        self.assertTrue(review_query_res["ok"])

        # Fetch queries for this study and check that a real clinical query has been created
        queries = self.request_json(f"/api/studies/{study_id}/queries", token=token)["queries"]
        real_query = next(q for q in queries if q["entry_id"] == entry["id"])
        self.assertEqual(real_query["field_code"], "age")
        self.assertEqual(real_query["status"], "open")

        # 12. Test recruitment metrics
        metrics = self.request_json(f"/api/studies/{study_id}/recruitment-metrics", token=token)
        self.assertEqual(metrics["total_participants"], 2)
        self.assertEqual(metrics["counts"]["enrolled"], 1)
        self.assertEqual(metrics["counts"]["screening"], 1)
