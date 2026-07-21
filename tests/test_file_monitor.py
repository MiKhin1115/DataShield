from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from dlp_agent.file_monitor import UsbFileMonitor


class UsbFileMonitorTests(TestCase):
    def test_reports_created_file_after_root_is_added(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            monitor = UsbFileMonitor()
            monitor.add_root(root)

            copied = root / "payroll.txt"
            copied.write_text("salary: 5000", encoding="utf-8")

            events = monitor.poll()

            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].path, copied)
            self.assertEqual(events[0].change_type, "created")

    def test_reports_modified_file(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            copied = root / "notes.txt"
            copied.write_text("public", encoding="utf-8")

            monitor = UsbFileMonitor()
            monitor.add_root(root)
            copied.write_text("confidential", encoding="utf-8")

            events = monitor.poll()

            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].change_type, "modified")

