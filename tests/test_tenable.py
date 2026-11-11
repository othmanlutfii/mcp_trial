import unittest
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
        "synopsis": "Original Tenable synopsis.",
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
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class TenableIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.config = patch.multiple(
            tenable.config,
            TENABLE_BASE_URL="https://tenable.example",
            ACCESS_KEY="test-access-key",
            SECRET_KEY="test-secret-key",
            TENABLE_CA_BUNDLE="",
            TENABLE_VERIFY_TLS=True,
            TENABLE_CONNECT_TIMEOUT=2,
            TENABLE_READ_TIMEOUT=10,
        )
        self.config.start()
        self.addCleanup(self.config.stop)

    def test_paginates_filters_and_summarizes_each_ip_without_duplicate_records(self):
        source_ip = "192.0.2.10"
        destination_ip = "192.0.2.20"
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    _page(
                        5,
                        [
                            _record(source_ip),
                            _record(destination_ip),
                        ],
                    ),
                ),
                FakeResponse(
                    200,
                    _page(
                        5,
                        [
                            _record(source_ip),
                            _record(
                                destination_ip,
                                plugin_id="informational",
                                severity_id=0,
                                severity="Informational",
                                cve=None,
                            ),
                        ],
                    ),
                ),
                FakeResponse(
                    200,
                    _page(5, [_record(source_ip, plugin_id="vpr-eight", vpr=8.0)]),
                ),
            ]
        )

        with patch.object(tenable, "PAGE_SIZE", 2), patch.object(
            tenable.requests, "Session", return_value=session
        ):
            result = tenable.get_connection_findings(source_ip, destination_ip)

        self.assertEqual(
            [call[1]["json"]["query"]["startOffset"] for call in session.calls],
            [0, 2, 4],
        )
        self.assertEqual(
            [call[1]["json"]["query"]["endOffset"] for call in session.calls],
            [2, 4, 6],
        )
        self.assertEqual(
            session.calls[0][0],
            "https://tenable.example/rest/analysis",
        )
        first_payload = session.calls[0][1]["json"]
        self.assertEqual(first_payload["type"], "vuln")
        self.assertEqual(first_payload["sourceType"], "cumulative")
        self.assertEqual(first_payload["query"]["tool"], "vulndetails")
        self.assertEqual(first_payload["query"]["startOffset"], 0)
        self.assertEqual(first_payload["query"]["endOffset"], 2)
        self.assertEqual(first_payload["query"]["sortField"], "vprScore")
        self.assertEqual(first_payload["query"]["sortDir"], "DESC")
        self.assertEqual(
            first_payload["query"]["filters"],
            [
                {"filterName": "ip", "operator": "=", "value": f"{source_ip},{destination_ip}"},
                {"filterName": "vprScore", "operator": "=", "value": "8.1-10"},
            ],
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
        self.assertEqual(result["overall_summary"]["total_findings"], 3)
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
                    "total_findings": 2,
                    "severity_summary": {
                        "critical": 0,
                        "high": 1,
                        "medium": 0,
                        "low": 0,
                    },
                },
            ],
        )
        self.assertEqual(
            result["vulnerabilities"][0],
            {
                "ip": source_ip,
                "plugin_id": "215966",
                "plugin_name": "Test vulnerability",
                "cve": "CVE-2024-12345",
                "vpr_score": 9.0,
                "severity": "High",
                "synopsis": "Original Tenable synopsis.",
                "solution": "Original Tenable solution.",
            },
        )
        self.assertIsNone(result["vulnerabilities"][2]["cve"])

    def test_severity_mapping_and_informational_total_are_consistent(self):
        ips = ["192.0.2.10"]
        results = [
            _record(ips[0], plugin_id=str(severity_id), severity_id=severity_id, severity=name)
            for severity_id, name in (
                (4, "Critical"),
                (3, "High"),
                (2, "Medium"),
                (1, "Low"),
                (0, "Informational"),
            )
        ]

        result = tenable._transform_results(ips, results)

        self.assertEqual(result["overall_summary"]["total_findings"], 5)
        self.assertEqual(
            result["overall_summary"]["severity_summary"],
            {"critical": 1, "high": 1, "medium": 1, "low": 1},
        )
        self.assertEqual(result["ip_summary"][0]["total_findings"], 5)

    def test_findings_on_distinct_ports_count_as_distinct_records_not_unique_cves(self):
        first = _record("192.0.2.10")
        first["port"] = 443
        second = _record("192.0.2.10")
        second["port"] = 8443

        result = tenable._transform_results(["192.0.2.10"], [first, second])

        self.assertEqual(result["overall_summary"]["total_findings"], 2)
        self.assertEqual(len(result["vulnerabilities"]), 2)
        self.assertEqual(
            [vulnerability["cve"] for vulnerability in result["vulnerabilities"]],
            ["CVE-2024-12345", "CVE-2024-12345"],
        )

    def test_empty_success_response_returns_zero_findings_for_both_ips(self):
        session = FakeSession([FakeResponse(200, _page(0, []))])
        with patch.object(tenable.requests, "Session", return_value=session):
            result = tenable.get_connection_findings("192.0.2.10", "192.0.2.20")

        self.assertEqual(result["overall_summary"]["total_findings"], 0)
        self.assertEqual(result["ip_summary"][0]["total_findings"], 0)
        self.assertEqual(result["ip_summary"][1]["total_findings"], 0)
        self.assertEqual(result["vulnerabilities"], [])

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
