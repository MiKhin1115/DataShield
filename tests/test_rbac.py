import tempfile
from pathlib import Path
from unittest import TestCase

from dlp_agent.rbac import SessionManager, UserStore, has_permission


class RbacTests(TestCase):
    def test_authenticates_default_roles_and_enforces_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = UserStore(Path(directory) / "users.json")
            administrator = store.authenticate("admin", "Admin123!")
            analyst = store.authenticate("soc", "Soc123!")
            auditor = store.authenticate("auditor", "Audit123!")
            viewer = store.authenticate("viewer", "View123!")

        self.assertTrue(has_permission(administrator, "policies.manage"))
        self.assertTrue(has_permission(analyst, "incidents.update"))
        self.assertTrue(has_permission(analyst, "case_attachments.download"))
        self.assertTrue(has_permission(analyst, "ai_analysis.generate"))
        self.assertFalse(has_permission(analyst, "policies.manage"))
        self.assertTrue(has_permission(auditor, "audit.view"))
        self.assertTrue(has_permission(auditor, "ai_analysis.view"))
        self.assertFalse(has_permission(auditor, "ai_analysis.generate"))
        self.assertFalse(has_permission(auditor, "incidents.update"))
        self.assertFalse(has_permission(auditor, "case_attachments.download"))
        self.assertTrue(has_permission(viewer, "dashboard.view"))
        self.assertFalse(has_permission(viewer, "ai_analysis.view"))
        self.assertFalse(has_permission(viewer, "audit.view"))

    def test_rejects_wrong_password_and_uses_server_side_session(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = UserStore(Path(directory) / "users.json")
            self.assertIsNone(store.authenticate("admin", "wrong-password"))
            user = store.authenticate("viewer", "View123!")
            sessions = SessionManager()
            token = sessions.create(user)

            self.assertEqual(sessions.get(token)["username"], "viewer")
            sessions.delete(token)
            self.assertIsNone(sessions.get(token))
