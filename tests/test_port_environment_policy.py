import unittest

from secbot.assessment import _connection_port_info
from secbot.policies import (
    DB_PORTS,
    classify_port,
    environment_rule,
    segment_rule,
)


def _side(asset_type, environment, registered=True):
    return {
        "registered": registered,
        "asset_type": asset_type,
        "environment": environment,
    }


class PortEnvironmentPolicyTests(unittest.TestCase):
    def test_http_server_to_server_same_environment_is_allowed_by_port_rule(self):
        source = _side("server", "PROD")
        destination = _side("server", "PROD")

        result = _connection_port_info(80, source, destination)

        self.assertEqual(result["level"], "ALLOW")
        self.assertEqual(result["rule"], "P-2")
        self.assertIn("environment yang sama", result["note"])

    def test_http_server_to_server_cross_environment_defers_to_environment_policy(self):
        source = _side("server", "DEV")
        destination = _side("server", "PROD")

        port_result = _connection_port_info(8080, source, destination)
        environment_result = environment_rule(
            source["environment"], destination["environment"]
        )

        self.assertEqual(port_result["level"], "ALLOW")
        self.assertIn("ENV.md", port_result["note"])
        self.assertEqual(environment_result["level"], "CONDITIONAL")
        self.assertEqual(environment_result["rule"], "S-3")

    def test_http_endpoint_to_server_is_allowed_by_port_and_environment_rules(self):
        source = _side("endpoint", "LAN")
        destination = _side("server", "DEV")

        port_result = _connection_port_info(80, source, destination)
        workstation_rule = segment_rule(
            "LAN Campus",
            "workstation",
            source["environment"],
            "Server Farm",
            "data",
            destination["environment"],
            80,
        )

        self.assertEqual(port_result["level"], "ALLOW")
        self.assertEqual(workstation_rule["level"], "ALLOW")
        self.assertEqual(workstation_rule["rule"], "W-1")

    def test_http_endpoint_to_production_server_remains_subject_to_workstation_rule(self):
        port_result = _connection_port_info(
            80, _side("endpoint", "LAN"), _side("server", "PROD")
        )
        workstation_rule = segment_rule(
            "LAN Campus",
            "workstation",
            "LAN",
            "Server Farm",
            "data",
            "PROD",
            80,
        )

        self.assertEqual(port_result["level"], "ALLOW")
        self.assertEqual(workstation_rule["level"], "CONDITIONAL")
        self.assertEqual(workstation_rule["rule"], "W-4")

    def test_http_unknown_or_unregistered_flow_keeps_exception_requirement(self):
        result = _connection_port_info(
            80,
            _side("server", None),
            _side("server", None, registered=False),
        )

        self.assertEqual(result["level"], "RESTRICTED")

    def test_https_is_preferred_and_custom_https_port_is_classified(self):
        for port in (443, 8443):
            with self.subTest(port=port):
                result = classify_port(port)
                self.assertTrue(result["service"].startswith("HTTPS"))
                self.assertEqual(result["level"], "PROHIBITED")
                self.assertEqual(result["rule"], "P-13")

    def test_https_is_allowed_for_server_to_server_and_endpoint_to_server(self):
        for port in (443, 8443):
            with self.subTest(port=port):
                server_result = _connection_port_info(
                    port, _side("server", "PROD"), _side("server", "PROD")
                )
                endpoint_result = _connection_port_info(
                    port, _side("endpoint", "LAN"), _side("server", "DEV")
                )

                self.assertEqual(server_result["level"], "ALLOW")
                self.assertEqual(endpoint_result["level"], "ALLOW")

    def test_https_other_directions_remain_default_deny(self):
        result = _connection_port_info(
            443,
            _side("server", "PROD"),
            _side("endpoint", "LAN"),
        )

        self.assertEqual(result["level"], "PROHIBITED")

    def test_lan_to_production_ssh_and_database_are_blocked_with_pam_guidance(self):
        for port in {22, *DB_PORTS}:
            with self.subTest(port=port):
                result = segment_rule(
                    "LAN Campus",
                    "workstation",
                    "LAN",
                    "Server Farm",
                    "data",
                    "PROD",
                    port,
                )

                self.assertEqual(result["level"], "BLOCK")
                self.assertEqual(result["rule"], "W-4")
                self.assertIn("gunakan PAM", result["note"])

    def test_lan_to_dev_ssh_and_database_follow_w1_and_port_rules(self):
        for port in {22, *DB_PORTS}:
            with self.subTest(port=port):
                result = segment_rule(
                    "LAN Campus",
                    "workstation",
                    "LAN",
                    "Server Farm",
                    "data",
                    "DEV",
                    port,
                )

                self.assertEqual(result["level"], "ALLOW")
                self.assertEqual(result["rule"], "W-1")

    def test_lan_to_serverfarm_management_ip_uses_ws2_port_and_environment_limits(self):
        nonprod_management_ssh = segment_rule(
            "LAN Campus",
            "workstation",
            "LAN",
            "Server Farm",
            "management",
            "DEV",
            22,
        )
        nonprod_management_database = segment_rule(
            "LAN Campus",
            "workstation",
            "LAN",
            "Server Farm",
            "management",
            "DEV",
            next(iter(DB_PORTS)),
        )
        prod_management_ssh = segment_rule(
            "LAN Campus",
            "workstation",
            "LAN",
            "Server Farm",
            "management",
            "PROD",
            22,
        )

        self.assertEqual(nonprod_management_ssh["level"], "ALLOW")
        self.assertEqual(nonprod_management_ssh["rule"], "WS-2")
        self.assertEqual(nonprod_management_database["level"], "BLOCK")
        self.assertEqual(nonprod_management_database["rule"], "WS-2")
        self.assertEqual(prod_management_ssh["level"], "BLOCK")
        self.assertEqual(prod_management_ssh["rule"], "WS-2")

    def test_http_server_to_endpoint_does_not_get_http_allow_rule(self):
        result = _connection_port_info(
            80,
            _side("server", "DEV"),
            _side("endpoint", "LAN"),
        )

        self.assertEqual(result["level"], "RESTRICTED")


if __name__ == "__main__":
    unittest.main()
