import unittest
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

import app
from secbot.agents import access_agents
from secbot.assessment import _side


def _assessment_data():
    return {
        "request": {
            "src_ip": "192.0.2.10",
            "dst_ip": "192.0.2.20",
            "port": 443,
            "protocol": "tcp",
        },
        "port_info": {
            "service": "HTTPS",
            "level": "RESTRICTED",
            "rule": "P-2",
        },
        "source": {
            "ip": "192.0.2.10",
            "registered": False,
            "asset_type": "unknown",
            "required_controls": [],
            "vuln": {"scanned": False, "counts": {}, "top": []},
            "sla": None,
        },
        "destination": {
            "ip": "192.0.2.20",
            "registered": False,
            "asset_type": "unknown",
            "required_controls": [],
            "vuln": {"scanned": False, "counts": {}, "top": []},
            "sla": None,
        },
        "conditions": [],
        "review_reasons": [],
        "policy_refs": ["P-2"],
        "preliminary_decision": "REVIEW_REQUIRED",
        "risk_level": "HIGH",
        "risk_score": 70,
        "finding_va_status": "failed",
        "finding_va_error": "TENABLE_PRIVATE_ERROR",
    }


class FakeLLM:
    def __init__(self):
        self.messages = None

    def invoke(self, messages):
        self.messages = messages
        return "Keputusan: REVIEW_REQUIRED"


class AccessReviewOutputTests(unittest.TestCase):
    def test_executive_summary_explains_decision_risk_and_concerns(self):
        data = _assessment_data()
        data["port_info"]["note"] = "HTTPS; tetap mengikuti aturan environment dan segmen"

        result = app._executive_summary(data)

        self.assertIn("belum dapat direkomendasikan", result["overview"])
        self.assertIn("Risiko tinggi", result["overview"])
        self.assertTrue(any("Aturan port:" in point for point in result["key_points"]))
        self.assertFalse(any("Catatan port:" in point for point in result["key_points"]))
        self.assertTrue(
            any("Compliance kontrol: Source" in point for point in result["key_points"])
        )
        self.assertTrue(
            any("Lengkapi data aset dan kontrol" in concern for concern in result["concerns"])
        )
        self.assertFalse(any("TENABLE_PRIVATE_ERROR" in item for item in result["concerns"]))

    def test_executive_summary_explains_allowed_cross_environment_connection(self):
        data = _assessment_data()
        data["source"].update(
            {
                "registered": True,
                "asset_type": "server",
                "environment": "DEV",
                "vuln": {"scanned": False, "counts": {}, "top": []},
            }
        )
        data["destination"].update(
            {
                "registered": True,
                "asset_type": "server",
                "environment": "UAT",
                "vuln": {"scanned": False, "counts": {}, "top": []},
            }
        )

        result = app._executive_summary(data)

        self.assertTrue(
            any(
                "Koneksi lintas environment DEV → UAT" in point
                and "S-1" in point
                for point in result["key_points"]
            )
        )

    def test_executive_summary_explains_conditional_cross_environment_connection(self):
        data = _assessment_data()
        data["source"].update(
            {
                "registered": True,
                "asset_type": "server",
                "environment": "UAT",
                "vuln": {"scanned": False, "counts": {}, "top": []},
            }
        )
        data["destination"].update(
            {
                "registered": True,
                "asset_type": "server",
                "environment": "PROD",
                "vuln": {"scanned": False, "counts": {}, "top": []},
            }
        )

        result = app._executive_summary(data)

        self.assertTrue(
            any(
                "Koneksi lintas environment UAT → PROD" in point
                and "S-4" in point
                for point in result["key_points"]
            )
        )
        self.assertTrue(
            any(
                "Akses lintas environment UAT → PROD bersyarat" in concern
                and "Exception Form" in concern
                for concern in result["concerns"]
            )
        )

    def test_executive_summary_lists_controls_that_comply_without_cmdb_wording(self):
        data = _assessment_data()
        data["source"] = {
            "ip": "192.0.2.10",
            "registered": True,
            "hostname": "app-server",
            "asset_type": "server",
            "required_controls": ["EDR", "VA"],
            "edr": True,
            "va": True,
            "pam": False,
            "gate": "PASS",
            "gate_missing": [],
            "vuln": {"scanned": False, "counts": {}, "top": []},
            "sla": None,
        }
        data["destination"] = {
            "ip": "192.0.2.20",
            "registered": True,
            "hostname": "db-server",
            "asset_type": "server",
            "required_controls": ["EDR", "VA"],
            "edr": True,
            "va": False,
            "pam": False,
            "gate": "FAIL",
            "gate_missing": ["VA"],
            "vuln": {"scanned": False, "counts": {}, "top": []},
            "sla": None,
        }

        result = app._executive_summary(data)

        self.assertTrue(
            any(
                "Compliance kontrol:" in point
                and "Source app-server" in point
                and "lengkap (wajib: EDR, VA; aktif: EDR, VA)" in point
                and "Destination db-server" in point
                and "belum lengkap; belum aktif VA" in point
                for point in result["key_points"]
            )
        )
        self.assertFalse(
            any("terdaftar di CMDB" in point for point in result["key_points"])
        )

    def test_executive_summary_shows_active_optional_controls_for_dev_server(self):
        data = _assessment_data()
        data["destination"] = _side("192.168.25.176")

        result = app._executive_summary(data)

        self.assertEqual(data["destination"]["required_controls"], ["EDR"])
        self.assertTrue(data["destination"]["edr"])
        self.assertTrue(data["destination"]["pam"])
        self.assertTrue(data["destination"]["va"])
        self.assertTrue(
            any(
                "Destination srv-idm-app03 (192.168.25.176): lengkap "
                "(wajib: EDR; aktif: EDR, PAM, VA)" in point
                for point in result["key_points"]
            )
        )

    def test_executive_summary_recommends_remediation_for_high_local_server_va(self):
        data = _assessment_data()
        data["source"].update(
            {
                "registered": True,
                "asset_type": "server",
                "hostname": "app-server",
                "vuln": {
                    "scanned": True,
                    "counts": {"High": 1},
                    "top": [{"severity": "High", "cvss": 8.2}],
                },
            }
        )

        result = app._executive_summary(data)

        self.assertTrue(
            any(
                "wajib ditindaklanjuti oleh tim server" in concern
                and "VA ulang" in concern
                for concern in result["concerns"]
            )
        )

    def test_executive_summary_recommends_remediation_for_tenable_vpr_over_eight(self):
        data = _assessment_data()
        data["destination"].update(
            {
                "registered": True,
                "asset_type": "server",
                "hostname": "db-server",
            }
        )
        data["finding_va_status"] = "success"
        data["finding_va"] = {
            "vulnerabilities": [
                {
                    "ip": "192.0.2.20",
                    "severity": "Medium",
                    "vpr_score": 8.7,
                    "plugin_name": "TENABLE_PRIVATE_FINDING",
                }
            ]
        }

        result = app._executive_summary(data)

        self.assertTrue(
            any(
                "db-server" in concern
                and "skor VPR/CVSS di atas 8" in concern
                and "wajib ditindaklanjuti oleh tim server" in concern
                for concern in result["concerns"]
            )
        )
        self.assertFalse(
            any("TENABLE_PRIVATE_FINDING" in concern for concern in result["concerns"])
        )

    def test_tenable_data_is_logged_only_for_verbose_cli_and_excluded_from_reviewer(self):
        for verbose in (False, True):
            with self.subTest(verbose=verbose):
                llm = FakeLLM()
                stdout = StringIO()
                with patch.object(access_agents, "_llm", return_value=llm), patch.object(
                    access_agents, "create_react_agent"
                ), patch.object(
                    access_agents,
                    "_run",
                    return_value=[SimpleNamespace(content="Gunakan aturan P-2.")],
                ), redirect_stdout(stdout):
                    access_agents.review_access(
                        "192.0.2.10",
                        "192.0.2.20",
                        443,
                        verbose=verbose,
                        assessment=_assessment_data(),
                    )

                reviewer_input = llm.messages[1][1]
                self.assertNotIn("finding_va", reviewer_input)
                self.assertNotIn("TENABLE_PRIVATE_ERROR", reviewer_input)
                if verbose:
                    self.assertIn("[Finding VA Tenable]", stdout.getvalue())
                    self.assertIn("TENABLE_PRIVATE_ERROR", stdout.getvalue())
                else:
                    self.assertNotIn("Finding VA Tenable", stdout.getvalue())
                    self.assertNotIn("TENABLE_PRIVATE_ERROR", stdout.getvalue())

    def test_web_answer_removes_markdown_decoration_and_normalizes_bullets(self):
        answer = (
            "**Keputusan:** REVIEW_REQUIRED\n"
            "3. Compliance:\n"
            "   - **EDR:** *Tidak tersedia.*\n"
            "   - `PAM`: belum aktif\n"
        )

        self.assertEqual(
            app._clean_ai_answer(answer),
            "Keputusan: REVIEW_REQUIRED\n"
            "3. Compliance:\n"
            "   • EDR: Tidak tersedia.\n"
            "   • PAM: belum aktif",
        )

    def test_assessment_page_does_not_render_tenable_result_or_error(self):
        result = _assessment_data()
        result.update(
            {
                "preliminary_decision": "REVIEW_REQUIRED",
                "risk_score": 70,
                "risk_level": "HIGH",
                "request": {
                    "src_ip": "192.0.2.10",
                    "dst_ip": "192.0.2.20",
                    "port": 443,
                    "protocol": "tcp",
                },
                "source": {
                    "ip": "192.0.2.10",
                    "registered": False,
                    "vuln": {"scanned": False, "counts": {}, "top": []},
                },
                "destination": {
                    "ip": "192.0.2.20",
                    "registered": False,
                    "vuln": {"scanned": False, "counts": {}, "top": []},
                },
                "port_info": {"service": "HTTPS", "level": "RESTRICTED"},
                "findings": [],
                "hard_blocks": [],
                "finding_va_status": "success",
                "finding_va": {"private_marker": "TENABLE_PRIVATE_FINDING"},
                "finding_va_error": "TENABLE_PRIVATE_ERROR",
            }
        )
        result["request"]["protocol"] = "udp"
        client = app.app.test_client()

        with patch("app.assess_connection_data", return_value=result) as assessment_mock, patch(
            "app._run_ai_review", return_value=("Jawaban rapi.", 0.1)
        ) as ai_review_mock:
            response = client.post(
                "/",
                data={
                    "src_ip": "192.0.2.10",
                    "dst_ip": "192.0.2.20",
                    "port": "443",
                    "service": "Internal HTTPS",
                    "protocol": "UDP",
                },
            )

        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Jawaban rapi.", page)
        self.assertIn("port 443/udp", page)
        self.assertIn("Service input: Internal HTTPS", page)
        self.assertIn("Klasifikasi port: HTTPS · RESTRICTED", page)
        self.assertIn("Executive Summary", page)
        self.assertIn("Concern dan tindak lanjut", page)
        self.assertNotIn("Tenable.sc", page)
        self.assertNotIn("TENABLE_PRIVATE_FINDING", page)
        self.assertNotIn("TENABLE_PRIVATE_ERROR", page)
        assessment_mock.assert_called_once_with(
            "192.0.2.10", "192.0.2.20", 443, "udp"
        )
        ai_review_mock.assert_called_once_with(
            "192.0.2.10", "192.0.2.20", 443, result, "udp"
        )

    def test_assessment_page_rejects_unsupported_protocol(self):
        client = app.app.test_client()

        with patch("app.assess_connection_data") as assessment_mock:
            response = client.post(
                "/",
                data={
                    "src_ip": "192.0.2.10",
                    "dst_ip": "192.0.2.20",
                    "port": "443",
                    "service": "HTTPS",
                    "protocol": "icmp",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Protocol harus TCP atau UDP.", response.get_data(as_text=True))
        assessment_mock.assert_not_called()

    def test_assessment_page_requires_manual_service(self):
        client = app.app.test_client()

        with patch("app.assess_connection_data") as assessment_mock:
            response = client.post(
                "/",
                data={
                    "src_ip": "192.0.2.10",
                    "dst_ip": "192.0.2.20",
                    "port": "22",
                    "protocol": "tcp",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Service wajib diisi.", response.get_data(as_text=True))
        assessment_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
