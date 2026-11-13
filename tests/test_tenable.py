import unittest
import sqlite3
import tempfile
from unittest.mock import patch

from secbot import assessment as connection_assessment
from secbot import tenable


def _record(
    ip,
    *,
    plugin_id="215966",
    vpr=9.0,
    severity_id=3,
    severity="High",
    cve="CVE-2024-12345",
):
    return {
        "ip": ip,
        "pluginID": plugin_id,
        "pluginName": "Test vulnerability",
        "cve": cve,
        "vprScore": vpr,
        "severity": {"id": severity_id, "name": severity},
        "riskFactor": severity,
        "cvssV3BaseScore": 8.8,
        "epssScore": 0.25,
        "exploitAvailable": True,
        "exploitFrameworks": ["Metasploit"],
        "port": 443,
        "protocol": "tcp",
        "dnsName": "server.example",
        "operatingSystem": "Linux",
        "synopsis": "Original Tenable synopsis.",
        "description": "Original Tenable description.",
        "solution": "Original Tenable solution.",
    }


def _page(total, results):
    return {
        "response": {
            "totalRecords": total,
            "returnedRecords": len(results),
            "results": results,
        }
    }


class FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self.body = body

    def json(self):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def close(self):
        pass

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if not self.responses:
            return FakeResponse(200, _page(0, []))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class TenableIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        tenable._database_initialized = False
        self.config = patch.multiple(
            tenable.config,
            TENABLE_BASE_URL="https://tenable.example",
            ACCESS_KEY="test-access-key",
            SECRET_KEY="test-secret-key",
            TENABLE_CA_BUNDLE="",
            TENABLE_VERIFY_TLS=True,
            TENABLE_CONNECT_TIMEOUT=2,
            TENABLE_READ_TIMEOUT=10,
            TENABLE_DB_PATH=f"{self.temp_dir.name}\\tenable.sqlite3",
            OLLAMA_URL="http://ollama.example",
            OLLAMA_LLM_MODEL="test-model",
            OLLAMA_CONNECT_TIMEOUT=2,
            OLLAMA_READ_TIMEOUT=10,
        )
        self.config.start()
        self.addCleanup(self.config.stop)
        self.addCleanup(setattr, tenable, "_database_initialized", False)
        self.ollama = patch.object(
            tenable, "_analyze_with_ollama", side_effect=lambda _: "Analisis dari Ollama"
        )
        self.ollama_mock = self.ollama.start()
        self.addCleanup(self.ollama.stop)

    def test_requests_each_ip_separately_and_persists_the_top_findings(self):
        source_ip = "192.0.2.10"
        destination_ip = "192.0.2.20"
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    _page(
                        1, [_record(source_ip)],
                    ),
                ),
                FakeResponse(
                    200,
                    _page(
                        1, [_record(destination_ip, plugin_id="destination-plugin")],
                    ),
                ),
            ]
        )

        with patch.object(tenable.requests, "Session", return_value=session):
            result = tenable.get_connection_findings(source_ip, destination_ip)

        self.assertEqual(len(session.calls), 2)
        self.assertEqual(
            session.calls[0][0],
            "https://tenable.example/rest/analysis",
        )
        first_payload = session.calls[0][1]["json"]
        self.assertEqual(first_payload["type"], "vuln")
        self.assertEqual(first_payload["sourceType"], "cumulative")
        self.assertEqual(first_payload["query"]["tool"], "vulndetails")
        self.assertEqual(first_payload["query"]["startOffset"], 0)
        self.assertEqual(first_payload["query"]["endOffset"], 3)
        self.assertEqual(first_payload["query"]["sortField"], "vprScore")
        self.assertEqual(first_payload["query"]["sortDir"], "DESC")
        self.assertEqual(
            first_payload["query"]["filters"],
            [
                {"filterName": "ip", "operator": "=", "value": source_ip},
                {"filterName": "vprScore", "operator": "=", "value": "8.1-10"},
            ],
        )
        self.assertEqual(
            session.calls[1][1]["json"]["query"]["filters"][0]["value"],
            destination_ip,
        )
        self.assertEqual(
            session.calls[0][1]["headers"]["x-apikey"],
            "accesskey=test-access-key; secretkey=test-secret-key",
        )
        self.assertEqual(
            session.calls[0][1]["timeout"],
            (2, 10),
        )
        self.assertTrue(session.calls[0][1]["verify"])
        self.assertFalse(session.calls[0][1]["allow_redirects"])
        self.assertEqual(result["overall_summary"]["total_ips"], 2)
        self.assertEqual(result["overall_summary"]["total_findings"], 2)
        self.assertEqual(
            result["overall_summary"]["severity_summary"],
            {"critical": 0, "high": 2, "medium": 0, "low": 0},
        )
        self.assertEqual(
            result["ip_summary"],
            [
                {
                    "ip": source_ip,
                    "total_findings": 1,
                    "severity_summary": {
                        "critical": 0,
                        "high": 1,
                        "medium": 0,
                        "low": 0,
                    },
                },
                {
                    "ip": destination_ip,
                    "total_findings": 1,
                    "severity_summary": {
                        "critical": 0,
                        "high": 1,
                        "medium": 0,
                        "low": 0,
                    },
                },
            ],
        )
        self.assertEqual(result["vulnerabilities"][0]["ip"], source_ip)
        self.assertEqual(result["vulnerabilities"][0]["synopsis"], "Original Tenable synopsis.")
        self.assertEqual(result["vulnerabilities"][0]["description"], "Original Tenable description.")
        self.assertEqual(result["vulnerabilities"][0]["ollama_analysis"], "Analisis dari Ollama")
        connection = sqlite3.connect(tenable.config.TENABLE_DB_PATH)
        try:
            rows = connection.execute(
                "SELECT ip, plugin_id, synopsis, description, solution, ollama_analysis "
                "FROM tenable_vulnerabilities ORDER BY ip"
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][3], "Original Tenable description.")
        self.assertEqual(rows[0][5], "Analisis dari Ollama")

    def test_severity_mapping_and_informational_total_are_consistent(self):
        ips = ["192.0.2.10"]
        results = [
            _record(ips[0], plugin_id=str(severity_id), severity_id=severity_id, severity=name)
            for severity_id, name in (
                (4, "Critical"),
                (3, "High"),
                (2, "Medium"),
            )
        ]

        result = tenable._transform_results(ips, results)

        self.assertEqual(result["overall_summary"]["total_findings"], 3)
        self.assertEqual(
            result["overall_summary"]["severity_summary"],
            {"critical": 1, "high": 1, "medium": 1, "low": 0},
        )
        self.assertEqual(result["ip_summary"][0]["total_findings"], 3)

    def test_plugin_id_is_the_unique_key_even_when_ports_differ(self):
        first = _record("192.0.2.10")
        first["port"] = 443
        second = _record("192.0.2.10")
        second["port"] = 8443

        result = tenable._transform_results(["192.0.2.10"], [first, second])

        self.assertEqual(result["overall_summary"]["total_findings"], 1)
        self.assertEqual(len(result["vulnerabilities"]), 1)
        self.assertEqual(result["vulnerabilities"][0]["cve"], "CVE-2024-12345")

    def test_empty_success_response_returns_zero_findings_for_both_ips(self):
        session = FakeSession([FakeResponse(200, _page(0, []))])
        with patch.object(tenable.requests, "Session", return_value=session):
            result = tenable.get_connection_findings("192.0.2.10", "192.0.2.20")

        self.assertEqual(result["overall_summary"]["total_findings"], 0)
        self.assertEqual(result["ip_summary"][0]["total_findings"], 0)
        self.assertEqual(result["ip_summary"][1]["total_findings"], 0)
        self.assertEqual(result["vulnerabilities"], [])
        self.assertEqual(
            [report["message"] for report in result["ip_reports"]],
            [
                "Tidak ada kerentanan VPR 8.1-10 yang ditemukan",
                "Tidak ada kerentanan VPR 8.1-10 yang ditemukan",
            ],
        )
        self.ollama_mock.assert_not_called()
        self.ollama.stop()

    def test_ollama_receives_database_analysis_fields_and_returns_model_text(self):
        record = {
            "ip": "192.0.2.10",
            "plugin_name": "Test vulnerability",
            "vpr_score": 9.1,
            "severity": "High",
            "cve": "CVE-2024-12345",
            "synopsis": "Synopsis from database",
            "description": "Description from database",
            "solution": "Solution from database",
        }
        response = FakeResponse(200, {"message": {"content": "Model output only"}})
        with patch.object(tenable.requests, "post", return_value=response) as post:
            answer = tenable._request_ollama_analysis(record)

        self.assertEqual(answer, "Model output only")
        args, kwargs = post.call_args
        self.assertEqual(args[0], "http://ollama.example/api/chat")
        self.assertEqual(kwargs["json"]["model"], "test-model")
        self.assertFalse(kwargs["json"]["stream"])
        prompt = kwargs["json"]["messages"][0]["content"]
        self.assertIn("- Synopsis: Synopsis from database", prompt)
        self.assertIn("- Description: Description from database", prompt)
        self.assertIn("- Solution: Solution from database", prompt)
        self.assertEqual(kwargs["timeout"], (2, 10))

    def test_cached_analysis_is_reused_on_next_assessment(self):
        ip = "192.0.2.10"
        session = FakeSession([
            FakeResponse(200, _page(1, [_record(ip)])),
            FakeResponse(200, _page(0, [])),
            FakeResponse(200, _page(1, [_record(ip)])),
            FakeResponse(200, _page(0, [])),
        ])
        with patch.object(tenable.requests, "Session", return_value=session):
            tenable.get_connection_findings(ip, "192.0.2.20")
            tenable.get_connection_findings(ip, "192.0.2.20")

        self.assertEqual(self.ollama_mock.call_count, 1)

    def test_ollama_timeout_retries_twice_and_returns_an_explicit_error(self):
        self.ollama.stop()
        ip = "192.0.2.10"
        session = FakeSession([
            FakeResponse(200, _page(1, [_record(ip)])),
            FakeResponse(200, _page(0, [])),
        ])
        with patch.object(tenable.requests, "Session", return_value=session), patch.object(
            tenable.requests, "post", side_effect=tenable.requests.Timeout
        ) as ollama_request:
            result = tenable.get_connection_findings(ip, "192.0.2.20")

        self.assertEqual(ollama_request.call_count, 3)
        self.assertEqual(result["analysis_status"], "failed")
        self.assertIn("timeout setelah 3 percobaan", result["analysis_errors"][0])
        self.assertIsNone(result["vulnerabilities"][0]["ollama_analysis"])
        self.assertIn("timeout", result["vulnerabilities"][0]["ollama_error"])

    def test_missing_ip_uses_ips_and_vuln_uuid_as_unique_key(self):
        result = tenable._transform_results(
            ["192.0.2.10"],
            [{
                "ips": ["192.0.2.10"],
                "vulnUUID": "uuid-1",
                "vprScore": 8.1,
                "severity": {"name": "High"},
            }],
        )

        self.assertEqual(result["vulnerabilities"][0]["ip"], "192.0.2.10")
        self.assertEqual(result["vulnerabilities"][0]["plugin_id"], "uuid-1")

    def test_invalid_credentials_http_response_is_an_error_not_an_empty_result(self):
        session = FakeSession([FakeResponse(401)])
        with patch.object(tenable.requests, "Session", return_value=session):
            with self.assertRaisesRegex(
                tenable.TenableIntegrationError, "Autentikasi Tenable gagal"
            ):
                tenable.get_connection_findings("192.0.2.10", "192.0.2.20")

    def test_invalid_json_response_is_an_error(self):
        session = FakeSession([FakeResponse(200, ValueError("invalid JSON"))])
        with patch.object(tenable.requests, "Session", return_value=session):
            with self.assertRaisesRegex(
                tenable.TenableIntegrationError, "bukan JSON yang valid"
            ):
                tenable.get_connection_findings("192.0.2.10", "192.0.2.20")

    def test_tenable_application_error_is_not_treated_as_empty_results(self):
        body = _page(0, [])
        body["response"]["error_code"] = 12
        session = FakeSession([FakeResponse(200, body)])
        with patch.object(tenable.requests, "Session", return_value=session):
            with self.assertRaisesRegex(
                tenable.TenableIntegrationError, "error API"
            ):
                tenable.get_connection_findings("192.0.2.10", "192.0.2.20")

    def test_connection_and_request_timeouts_are_reported(self):
        for error, message in (
            (tenable.requests.ConnectTimeout(), "Koneksi ke Tenable mengalami timeout"),
            (tenable.requests.ReadTimeout(), "Request ke Tenable mengalami timeout"),
        ):
            with self.subTest(error=type(error).__name__):
                session = FakeSession([error])
                with patch.object(tenable.requests, "Session", return_value=session):
                    with self.assertRaisesRegex(tenable.TenableIntegrationError, message):
                        tenable.get_connection_findings("192.0.2.10", "192.0.2.20")

    def test_tls_and_proxy_failures_are_reported_without_request_secrets(self):
        for error, message, log_marker in (
            (
                tenable.requests.exceptions.SSLError("certificate verify failed"),
                "Verifikasi sertifikat TLS Tenable gagal",
                "error=tls_error exception_type=SSLError",
            ),
            (
                tenable.requests.exceptions.ProxyError("proxy unavailable"),
                "Koneksi proxy ke Tenable gagal",
                "error=proxy_error exception_type=ProxyError",
            ),
            (
                tenable.requests.ConnectionError("name resolution failed"),
                "Tidak dapat terhubung ke Tenable",
                "error=connection_error exception_type=ConnectionError",
            ),
        ):
            with self.subTest(error=type(error).__name__):
                session = FakeSession([error])
                with patch.object(tenable.requests, "Session", return_value=session):
                    with self.assertLogs(tenable.logger, level="ERROR") as logs:
                        with self.assertRaisesRegex(tenable.TenableIntegrationError, message):
                            tenable.get_connection_findings(
                                "192.0.2.10", "192.0.2.20"
                            )
                self.assertIn(log_marker, logs.output[0])
                self.assertNotIn("test-access-key", logs.output[0])
                self.assertNotIn("test-secret-key", logs.output[0])

    def test_custom_tenable_ca_bundle_is_passed_to_requests(self):
        session = FakeSession([FakeResponse(200, _page(0, []))])
        with patch.object(
            tenable.config, "TENABLE_CA_BUNDLE", "C:/certs/tenable-ca.pem"
        ), patch.object(tenable.requests, "Session", return_value=session):
            tenable.get_connection_findings("192.0.2.10", "192.0.2.20")

        self.assertEqual(
            session.calls[0][1]["verify"],
            "C:/certs/tenable-ca.pem",
        )

    def test_tls_verification_can_be_disabled_explicitly_with_warning(self):
        session = FakeSession([FakeResponse(200, _page(0, []))])
        with patch.object(tenable.config, "TENABLE_VERIFY_TLS", False), patch.object(
            tenable.requests, "Session", return_value=session
        ), self.assertLogs(tenable.logger, level="WARNING") as logs:
            tenable.get_connection_findings("192.0.2.10", "192.0.2.20")

        self.assertFalse(session.calls[0][1]["verify"])
        self.assertIn("TLS certificate verification is disabled", logs.output[0])

    def test_assessment_keeps_va_failure_distinct_from_empty_findings(self):
        with patch.object(
            connection_assessment.tenable,
            "get_connection_findings",
            side_effect=tenable.TenableIntegrationError("Tenable tidak tersedia."),
        ):
            result = connection_assessment.assess_connection_data(
                "192.168.5.22", "10.45.56.143", 443
            )

        self.assertEqual(result["finding_va_status"], "failed")
        self.assertEqual(result["finding_va_error"], "Tenable tidak tersedia.")
        self.assertNotIn("finding_va", result)


if __name__ == "__main__":
    unittest.main()
