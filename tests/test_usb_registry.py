import tempfile
from pathlib import Path
from unittest import TestCase

from dlp_agent.usb_registry import UsbRegistry


class UsbRegistryTests(TestCase):
    def test_tracks_authorization_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = UsbRegistry(Path(directory) / "usb.json")
            self.assertEqual(registry.status("E:"), "unknown")
            registry.upsert("E:", "Company USB", "authorized")
            self.assertEqual(registry.status("e:"), "authorized")
            self.assertEqual(registry.status("SERIAL-1", "E:"), "authorized")
            registry.upsert("E:", "Company USB", "blocked")
            self.assertEqual(registry.status("E:"), "blocked")
            self.assertTrue(registry.delete("E:"))
