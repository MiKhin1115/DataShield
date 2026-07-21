from unittest import TestCase

from dlp_agent.alerting import SocAlerter


class SocAlerterTests(TestCase):
    def test_does_not_alert_for_allowed_activity(self) -> None:
        alerter = SocAlerter()

        self.assertEqual(alerter.notify({"policy_decision": "Allow"}), [])

    def test_sends_console_and_webhook_alerts(self) -> None:
        requests: list[object] = []

        def sender(request: object, timeout: float) -> object:
            requests.append((request, timeout))
            return object()

        alerter = SocAlerter("https://alerts.example.test", sender)
        results = alerter.notify(
            {
                "policy_decision": "Block",
                "risk_score": 95,
                "file_classification": "Restricted",
                "user_name": "test-user",
                "file_name": "credentials.env",
                "device_name": "Test USB",
                "incident_id": "INC-TEST",
            }
        )

        self.assertEqual([result.channel for result in results], ["console", "webhook"])
        self.assertTrue(all(result.sent for result in results))
        self.assertEqual(len(requests), 1)
