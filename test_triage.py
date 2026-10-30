import unittest

from src.triage import triage_alert, triage_alerts


class TriageTests(unittest.TestCase):
    def test_critical_alert_is_scored_and_prioritised(self):
        alert = {
            "id": "TEST-1",
            "severity": "critical",
            "asset_criticality": "critical",
            "known_malicious_ip": True,
            "event_type": "data_exfiltration",
        }
        result = triage_alert(alert)
        self.assertEqual(result["risk_score"], 95)
        self.assertEqual(result["priority"], "Critical")

    def test_low_signal_alert_is_low_priority(self):
        result = triage_alert({"id": "TEST-2", "severity": "low",
                               "asset_criticality": "low"})
        self.assertEqual(result["priority"], "Low")
        self.assertGreaterEqual(result["risk_score"], 0)

    def test_success_after_failures_adds_reason(self):
        result = triage_alert({
            "id": "TEST-3",
            "successful_login_after_failures": True,
            "failed_logins": 12,
        })
        self.assertTrue(any("Successful login" in x for x in result["reasons"]))

    def test_alerts_sorted_highest_first(self):
        results = triage_alerts([
            {"id": "LOW", "severity": "low"},
            {"id": "HIGH", "severity": "critical"},
        ])
        self.assertEqual(results[0]["id"], "HIGH")


if __name__ == "__main__":
    unittest.main()
