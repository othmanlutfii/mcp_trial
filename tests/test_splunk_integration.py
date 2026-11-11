import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app
from secbot import splunk_assets, splunk_client


def _asset(ip="192.0.2.10", asset_id="A-1", **changes):
    row = {
        "Asset ID": asset_id,
        "IP": ip,
        "hostname": "test-server",
        "asset_type": "server",
        "EDR": "true",
        "PAM": "yes",
        "SPLUNK": 1,
        "VA": "false",
        "Segment": "Server Farm",
        "category": "data",
        "environment": "DEV",
        "os_version": "Windows Server",
        "pic": "Ops",
        "priority": "P2",
    }
    row.update(changes)
    return row


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.body = body

    def json(self):
        return self.body


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)

    def close(self):
        self.closed = True


class SplunkDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_patch = patch.multiple(
            splunk_assets.config,
            SPLUNK_ASSETS_DB_PATH=Path(self.temp_dir.name) / "assets.sqlite3",
            PROJECT_ROOT=Path(__file__).resolve().parents[1],
        )
        self.config_patch.start()
        self.addCleanup(self.config_patch.stop)
        self.addCleanup(self.temp_dir.cleanup)
        self.migration_patch = patch.object(splunk_assets, "_migration_complete", False)
        self.migration_patch.start()
        self.addCleanup(self.migration_patch.stop)

    def test_upsert_maps_fields_deduplicates_and_preserves_old_assets(self):
        inserted, updated = splunk_assets.upsert_assets(
            [
                _asset(),
                _asset(hostname="updated-server", EDR="active"),
                _asset(ip="192.0.2.11", asset_id="A-2"),
            ]
        )

        self.assertEqual((inserted, updated), (2, 0))
        assets, total = splunk_assets.list_assets(page=1, per_page=10)
        self.assertEqual(total, 2)
        first = next(asset for asset in assets if asset["source_id"] == "A-1")
        self.assertEqual(first["ip"], "192.0.2.10")
        self.assertEqual(first["hostname"], "updated-server")
        self.assertEqual((first["edr"], first["pam"], first["splunk"], first["va"]), (1, 1, 1, 0))
        self.assertEqual(json.loads(first["raw_json"])["hostname"], "updated-server")

        inserted, updated = splunk_assets.upsert_assets([_asset(asset_id="A-1")])
        self.assertEqual((inserted, updated), (0, 1))
        self.assertEqual(splunk_assets.list_assets(page=1, per_page=10)[1], 2)

    def test_fallback_identity_and_failed_batch_are_safe(self):
        first = _asset()
        first.pop("Asset ID")
        inserted, updated = splunk_assets.upsert_assets([first])
        self.assertEqual((inserted, updated), (1, 0))

        broken = {"IP": "192.0.2.99", "hostname": "missing-type"}
        with self.assertRaises(splunk_assets.AssetDataError):
            splunk_assets.upsert_assets([_asset(asset_id="new"), broken])
        self.assertEqual(splunk_assets.list_assets(page=1, per_page=10)[1], 1)

    def test_orphaned_sync_run_is_marked_failed_during_database_initialization(self):
        splunk_assets.initialize_database()
        with splunk_assets._database() as connection:
            cursor = connection.execute(
                "INSERT INTO splunk_sync_runs(status, worker_pid, started_at) "
                "VALUES ('running', 999999, '2026-01-01T00:00:00+00:00')"
            )
            run_id = cursor.lastrowid

        with patch.object(splunk_assets, "_migration_complete", False):
            splunk_assets.initialize_database()

        run = splunk_assets.get_sync_run(run_id)
        self.assertEqual(run["status"], "failed")
        self.assertIn("proses aplikasi sebelumnya", run["error_message"].casefold())

    def test_sync_success_and_failure_are_recorded(self):
        class ImmediateThread:
            def __init__(self, target, args, **kwargs):
                self.target = target
                self.args = args

            def start(self):
                self.target(*self.args)

        with patch.object(splunk_assets.threading, "Thread", ImmediateThread), patch.object(
            splunk_assets, "run_asset_lookup", return_value=("sid-1", [_asset()])
        ):
            run, created = splunk_assets.enqueue_sync()
        self.assertTrue(created)
        self.assertEqual(run["status"], "succeeded")
        self.assertEqual((run["rows_received"], run["inserted_count"]), (1, 1))
        self.assertEqual(run["sid"], "sid-1")

        with patch.object(splunk_assets.threading, "Thread", ImmediateThread), patch.object(
            splunk_assets.config, "SPLUNK_TOKEN", "secret-token"
        ), patch.object(
            splunk_assets,
            "run_asset_lookup",
            side_effect=splunk_client.SplunkIntegrationError(
                "request failed secret-token", sid="sid-failed"
            ),
        ):
            failed_run, _ = splunk_assets.enqueue_sync()
        self.assertEqual(failed_run["status"], "failed")
        self.assertEqual(failed_run["sid"], "sid-failed")
        self.assertNotIn("secret-token", failed_run["error_message"])

    def test_active_sync_is_reused(self):
        class QueuedThread:
            def __init__(self, **kwargs):
                pass

            def start(self):
                pass

        with patch.object(splunk_assets.threading, "Thread", QueuedThread):
            first, created = splunk_assets.enqueue_sync()
            second, created_second = splunk_assets.enqueue_sync()
        self.assertTrue(created)
        self.assertFalse(created_second)
        self.assertEqual(first["id"], second["id"])


class SplunkClientTests(unittest.TestCase):
    def test_search_job_and_result_pagination_use_configured_tls(self):
        session = FakeSession(
            [
                FakeResponse(201, {"sid": "job/1"}),
                FakeResponse(
                    200,
                    {"entry": [{"content": {"dispatchState": "DONE", "isDone": True}}]},
                ),
                FakeResponse(200, {"results": [{"IP": "192.0.2.10"}]}),
            ]
        )
        with patch.multiple(
            splunk_client.config,
            SPLUNK_HOST="https://splunk.example",
            SPLUNK_PORT=8089,
            SPLUNK_TOKEN="splunk-token",
            SPLUNK_VERIFY_TLS=True,
            SPLUNK_CA_BUNDLE="",
            SPLUNK_CONNECT_TIMEOUT=2,
            SPLUNK_READ_TIMEOUT=5,
            SPLUNK_JOB_TIMEOUT=10,
            SPLUNK_POLL_INTERVAL=0,
        ), patch.object(splunk_client.requests, "Session", return_value=session):
            sid, rows = splunk_client.run_asset_lookup()

        self.assertEqual(sid, "job/1")
        self.assertEqual(rows, [{"IP": "192.0.2.10"}])
        create = session.calls[0]
        self.assertEqual(create[0], "POST")
        self.assertEqual(create[2]["data"]["search"], "| inputlookup bni_asset_universe")
        self.assertEqual(
            create[2]["headers"]["Authorization"], "Splunk splunk-token"
        )
        self.assertTrue(create[2]["verify"])
        self.assertIn("/services/search/jobs/job%2F1/results", session.calls[-1][1])
        self.assertTrue(session.closed)

    def test_result_fetch_continues_until_all_pages_are_read(self):
        first_page = [{"IP": f"192.0.2.{index % 254 + 1}"} for index in range(500)]
        session = FakeSession(
            [
                FakeResponse(201, {"sid": "job-2"}),
                FakeResponse(
                    200,
                    {"entry": [{"content": {"dispatchState": "DONE", "isDone": True}}]},
                ),
                FakeResponse(200, {"results": first_page}),
                FakeResponse(200, {"results": [{"IP": "198.51.100.1"}]}),
            ]
        )
        with patch.multiple(
            splunk_client.config,
            SPLUNK_HOST="splunk.example",
            SPLUNK_PORT=8089,
            SPLUNK_TOKEN="token",
            SPLUNK_VERIFY_TLS=True,
            SPLUNK_CA_BUNDLE="",
            SPLUNK_CONNECT_TIMEOUT=2,
            SPLUNK_READ_TIMEOUT=5,
            SPLUNK_JOB_TIMEOUT=10,
            SPLUNK_POLL_INTERVAL=0,
        ), patch.object(splunk_client.requests, "Session", return_value=session):
            _, rows = splunk_client.run_asset_lookup()

        self.assertEqual(len(rows), 501)
        self.assertEqual(session.calls[-2][2]["params"]["offset"], 0)
        self.assertEqual(session.calls[-1][2]["params"]["offset"], 500)

    def test_search_error_messages_and_http_auth_errors_fail(self):
        session = FakeSession(
            [FakeResponse(200, {"messages": [{"type": "ERROR", "text": "lookup failed"}]})]
        )
        with patch.multiple(
            splunk_client.config,
            SPLUNK_HOST="splunk.example",
            SPLUNK_PORT=8089,
            SPLUNK_TOKEN="token",
            SPLUNK_VERIFY_TLS=True,
            SPLUNK_CA_BUNDLE="",
            SPLUNK_CONNECT_TIMEOUT=2,
            SPLUNK_READ_TIMEOUT=5,
            SPLUNK_JOB_TIMEOUT=10,
            SPLUNK_POLL_INTERVAL=1,
        ), patch.object(splunk_client.requests, "Session", return_value=session):
            with self.assertRaisesRegex(
                splunk_client.SplunkIntegrationError, "lookup failed"
            ):
                splunk_client.run_asset_lookup()

    def test_http_forbidden_response_is_reported_as_auth_failure(self):
        session = FakeSession([FakeResponse(403, {"messages": []})])
        with patch.multiple(
            splunk_client.config,
            SPLUNK_HOST="splunk.example",
            SPLUNK_PORT=8089,
            SPLUNK_TOKEN="token",
            SPLUNK_VERIFY_TLS=True,
            SPLUNK_CA_BUNDLE="",
            SPLUNK_CONNECT_TIMEOUT=2,
            SPLUNK_READ_TIMEOUT=5,
        ), patch.object(splunk_client.requests, "Session", return_value=session):
            with self.assertRaisesRegex(
                splunk_client.SplunkIntegrationError, "tidak memiliki izin"
            ):
                splunk_client.run_asset_lookup()


class SplunkRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_patch = patch.multiple(
            splunk_assets.config,
            SPLUNK_ASSETS_DB_PATH=Path(self.temp_dir.name) / "assets.sqlite3",
            PROJECT_ROOT=Path(__file__).resolve().parents[1],
            SPLUNK_ASSETS_READ_TOKEN="read-token",
            SPLUNK_ASSETS_SYNC_TOKEN="sync-token",
            SPLUNK_ASSETS_UI_USERNAME="viewer",
            SPLUNK_ASSETS_UI_PASSWORD="ui-password",
        )
        self.config_patch.start()
        self.addCleanup(self.config_patch.stop)
        self.addCleanup(self.temp_dir.cleanup)
        self.migration_patch = patch.object(splunk_assets, "_migration_complete", False)
        self.migration_patch.start()
        self.addCleanup(self.migration_patch.stop)
        self.client = app.app.test_client()

    @staticmethod
    def _bearer(token):
        return {"Authorization": f"Bearer {token}"}

    def test_sync_read_status_and_asset_routes_enforce_auth(self):
        unauthorized = self.client.post("/api/splunk/assets/sync")
        self.assertEqual(unauthorized.status_code, 401)

        class QueuedThread:
            def __init__(self, **kwargs):
                pass

            def start(self):
                pass

        with patch.object(splunk_assets.threading, "Thread", QueuedThread):
            response = self.client.post(
                "/api/splunk/assets/sync", headers=self._bearer("sync-token")
            )
        self.assertEqual(response.status_code, 202)
        run_id = response.get_json()["run_id"]

        status_response = self.client.get(
            f"/api/splunk/assets/sync/{run_id}",
            headers=self._bearer("read-token"),
        )
        self.assertEqual(status_response.status_code, 200)
        self.assertEqual(status_response.get_json()["status"], "queued")
        self.assertNotIn("worker_pid", status_response.get_json())

        assets_response = self.client.get(
            "/api/splunk/assets?page=1&per_page=10",
            headers=self._bearer("read-token"),
        )
        self.assertEqual(assets_response.status_code, 200)
        self.assertEqual(assets_response.get_json()["total"], 0)
        splunk_assets.upsert_assets([_asset()])
        populated_response = self.client.get(
            "/api/splunk/assets?q=test-server&environment=DEV",
            headers=self._bearer("read-token"),
        )
        self.assertEqual(populated_response.status_code, 200)
        self.assertEqual(populated_response.get_json()["total"], 1)
        self.assertNotIn("raw_json", populated_response.get_json()["items"][0])
        self.assertNotIn("source_key", populated_response.get_json()["items"][0])
        self.assertEqual(
            self.client.get("/api/splunk/assets?page=bad", headers=self._bearer("read-token")).status_code,
            400,
        )
        self.assertEqual(
            self.client.get("/api/splunk/assets").status_code,
            401,
        )

    def test_ui_is_basic_authenticated_and_reads_database(self):
        splunk_assets.upsert_assets([_asset()])
        self.assertEqual(self.client.get("/splunk/assets").status_code, 401)
        credentials = base64.b64encode(b"viewer:ui-password").decode("ascii")
        response = self.client.get(
            "/splunk/assets",
            headers={"Authorization": f"Basic {credentials}"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"test-server", response.data)
        self.assertIn(b"1 aset tersimpan", response.data)


if __name__ == "__main__":
    unittest.main()
