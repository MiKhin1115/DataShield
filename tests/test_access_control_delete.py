from pathlib import Path
from unittest import TestCase


class AccessControlDeleteTests(TestCase):
    def test_usb_delete_uses_dashboard_confirmation_and_encoded_endpoint(self) -> None:
        html = Path("dlp_agent/dashboard_assets/index.html").read_text(encoding="utf-8")
        script = Path("dlp_agent/dashboard_assets/app.js").read_text(encoding="utf-8")

        self.assertIn('id="usb-delete-dialog"', html)
        self.assertIn('id="usb-delete-confirm"', html)
        self.assertIn("function requestUsbDeletion", script)
        self.assertIn("async function confirmUsbDeletion", script)
        self.assertIn("encodeURIComponent(deviceId)", script)
        self.assertIn('method: "DELETE"', script)
        self.assertNotIn('window.confirm("Remove this USB device registration?")', script)
