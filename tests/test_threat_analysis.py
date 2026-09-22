import unittest

from ioc.threat_analysis import analyzeThreat, determineThreatState


class TestThreatAnalysis(unittest.TestCase):
    def _base(self):
        return {
            "evidence": {
                "attack_prevented": False,
                "scanning_or_recon": False,
                "phishing_or_social_eng": False,
                "exploit_attempt": False,
                "web_exploit_payload": False,
                "malware_executed": False,
                "c2_connection": False,
                "privilege_escalation": False,
                "lateral_movement": False,
                "persistence_mechanism": False,
                "data_exfiltration": False,
                "service_disruption_or_encryption": False,
            },
            "mitre_tactics": [],
            "risk_notes": [],
            "asset_criticality": "standard",
        }

    def test_exposure_only(self):
        data = self._base()
        data["risk_notes"] = ["Outdated service exposed"]
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Exposure")
        self.assertEqual(out["threat_level"], "Low")
        self.assertEqual(out["verdict"], "False Positive")

    def test_recon_replaces_exposure(self):
        data = self._base()
        data["evidence"]["scanning_or_recon"] = True
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Reconnaissance")
        self.assertEqual(out["threat_level"], "Low")
        self.assertEqual(out["verdict"], "Benign Positive")

    def test_recon_blocked_stays_low(self):
        data = self._base()
        data["evidence"]["scanning_or_recon"] = True
        data["evidence"]["attack_prevented"] = True
        data["device_action"] = "Blocked"
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Reconnaissance")
        self.assertEqual(out["threat_level"], "Low")

    def test_phishing_is_delivery(self):
        data = self._base()
        data["evidence"]["phishing_or_social_eng"] = True
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Delivery")
        self.assertEqual(out["threat_level"], "Low")
        self.assertEqual(out["verdict"], "Benign Positive")

    def test_provider_exploit_reputation_is_delivery_not_exploitation(self):
        # "This IP attacked elsewhere" is not a payload aimed at this app.
        data = self._base()
        data["evidence"]["exploit_attempt"] = True
        self.assertEqual(determineThreatState(data), "Delivery")

    def test_web_exploit_payload_is_exploitation_at_medium(self):
        data = self._base()
        data["evidence"]["exploit_attempt"] = True
        data["evidence"]["web_exploit_payload"] = True
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Exploitation")
        self.assertEqual(out["threat_level"], "Medium")
        # Medium is not a True Positive level, and Exploitation proves no success.
        self.assertEqual(out["verdict"], "Benign Positive")

    def test_web_exploit_payload_blocked_is_still_exploitation_at_medium(self):
        data = self._base()
        data["evidence"]["exploit_attempt"] = True
        data["evidence"]["web_exploit_payload"] = True
        data["device_action"] = "Blocked"
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Exploitation")
        self.assertEqual(out["threat_level"], "Medium")

    def test_exploitation_outranks_recon(self):
        data = self._base()
        data["evidence"]["scanning_or_recon"] = True
        data["evidence"]["exploit_attempt"] = True
        data["evidence"]["web_exploit_payload"] = True
        self.assertEqual(determineThreatState(data), "Exploitation")

    def test_exploitation_outranks_delivery(self):
        data = self._base()
        data["evidence"]["phishing_or_social_eng"] = True
        data["evidence"]["web_exploit_payload"] = True
        self.assertEqual(determineThreatState(data), "Exploitation")

    def test_server_side_execution_outranks_exploitation(self):
        data = self._base()
        data["evidence"]["web_exploit_payload"] = True
        data["evidence"]["malware_executed"] = True
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Execution")
        self.assertEqual(out["verdict"], "True Positive")

    def test_prevented_execution_caps_at_delivery(self):
        data = self._base()
        data["evidence"]["malware_executed"] = True
        data["device_action"] = "Quarantined"
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Delivery")
        self.assertEqual(out["threat_level"], "Low")

    def test_execution_by_malware_execution(self):
        data = self._base()
        data["evidence"]["malware_executed"] = True
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Execution")
        self.assertEqual(out["threat_level"], "Medium")

    def test_execution_on_critical_asset_is_high(self):
        data = self._base()
        data["evidence"]["malware_executed"] = True
        data["asset_criticality"] = "critical"
        self.assertEqual(analyzeThreat(data)["threat_level"], "High")

    def test_privilege_escalation(self):
        data = self._base()
        data["evidence"]["privilege_escalation"] = True
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Privilege Escalation")
        self.assertIn(out["threat_level"], ("High", "Very High"))

    def test_lateral_movement(self):
        data = self._base()
        data["evidence"]["lateral_movement"] = True
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Lateral Movement")
        self.assertIn(out["threat_level"], ("High", "Very High"))

    def test_impact_override(self):
        data = self._base()
        data["evidence"]["data_exfiltration"] = True
        data["evidence"]["lateral_movement"] = True
        out = analyzeThreat(data)
        self.assertEqual(out["threat_state"], "Impact")
        self.assertEqual(out["threat_level"], "Very High")

    def test_highest_severity_priority(self):
        data = self._base()
        data["evidence"]["malware_executed"] = True
        data["evidence"]["persistence_mechanism"] = True
        self.assertEqual(determineThreatState(data), "Persistence")


if __name__ == "__main__":
    unittest.main()
