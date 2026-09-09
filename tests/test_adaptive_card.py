import unittest

from teams.adaptive_card import build_adaptive_card


class AdaptiveCardTests(unittest.TestCase):
    def setUp(self):
        self.incident = {
            "id": "f49d731e-c4c4-4778-84a6-d26a4df663bd",
            "risk_score": 70,
            "severity": "high",
        }

        self.action = {
            "id": "11111111-1111-4111-8111-111111111111",
            "incident_id": self.incident["id"],
            "action_type": "close_nsg_rule",
            "status": "pending",
        }

    def test_build_pending_action_card(self):
        card = build_adaptive_card(
            incident=self.incident,
            action=self.action,
            analysis={
                "title": "Public SSH Access Detected",
                "summary": "Public SSH access requires review.",
            },
        )

        self.assertEqual(card["type"], "AdaptiveCard")
        self.assertEqual(len(card["actions"]), 2)

        self.assertEqual(
            card["actions"][0]["data"]["sentinelmind_action"],
            "approve",
        )

        self.assertEqual(
            card["actions"][1]["data"]["sentinelmind_action"],
            "reject",
        )

    def test_non_pending_action_rejected(self):
        action = dict(self.action)
        action["status"] = "approved"

        with self.assertRaises(ValueError):
            build_adaptive_card(
                incident=self.incident,
                action=action,
            )

    def test_incident_mismatch_rejected(self):
        action = dict(self.action)
        action["incident_id"] = (
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        )

        with self.assertRaises(ValueError):
            build_adaptive_card(
                incident=self.incident,
                action=action,
            )

    def test_unknown_action_type_rejected(self):
        action = dict(self.action)
        action["action_type"] = "delete_everything"

        with self.assertRaises(ValueError):
            build_adaptive_card(
                incident=self.incident,
                action=action,
            )


if __name__ == "__main__":
    unittest.main()
