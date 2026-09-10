import tempfile
from pathlib import Path
from unittest import TestCase

from dlp_agent.usb_registry import UsbRegistry


class UsbRegistryTests(TestCase):
    def test_tracks_authorization_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = UsbRegistry(Path(directory) / "usb.json")
            self.assertEqual(registry.status("SERIAL-1"), "unknown")
            registry.upsert("SERIAL-1", "Company USB", "authorized")
            self.assertEqual(registry.status("serial-1"), "authorized")
            self.assertEqual(registry.status(" OTHER-SERIAL "), "unknown")
            registry.upsert("SERIAL-1", "Company USB", "blocked")
            self.assertEqual(registry.status("SERIAL-1"), "blocked")
            self.assertTrue(registry.delete("SERIAL-1"))

    def test_normalizes_serial_and_ignores_display_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = UsbRegistry(Path(directory) / "usb.json")
            registry.upsert(" SERIAL-1 ", "Company USB", "authorized")
            self.assertEqual(registry.status(" serial-1 "), "authorized")
            self.assertEqual(registry.status("Company USB"), "unknown")
            self.assertEqual(registry.status(""), "unknown")
            registry.upsert("serial-1", "Renamed USB", "blocked")
            self.assertEqual(len(registry.list()), 1)
            self.assertEqual(registry.status("SERIAL-1"), "blocked")
            self.assertTrue(registry.delete(" SERIAL-1 "))

    def test_rejects_drive_letters_and_device_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = UsbRegistry(Path(directory) / "usb.json")
            for identity in ("E:", "USBSTOR\\DISK&VEN_TEST", ""):
                with self.subTest(identity=identity), self.assertRaises(ValueError):
                    registry.upsert(identity, "Company USB", "authorized")