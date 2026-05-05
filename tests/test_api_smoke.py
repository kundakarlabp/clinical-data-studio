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


if __name__ == "__main__":
    unittest.main()
