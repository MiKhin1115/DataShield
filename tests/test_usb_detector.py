from unittest import TestCase

from dlp_agent.usb_detector import UsbDetector, UsbDevice


class FakeProvider:
    def __init__(self, snapshots: list[list[UsbDevice]]) -> None:
        self.snapshots = snapshots
        self.index = 0

    def list_devices(self) -> list[UsbDevice]:
        snapshot = self.snapshots[min(self.index, len(self.snapshots) - 1)]
        self.index += 1
        return snapshot


class UsbDetectorTests(TestCase):
    def test_reports_insert_and_remove_events(self) -> None:
        device = UsbDevice(
            device_id="E:",
            drive="E:\\",
            name="Kingston",
            volume_name="Kingston",
            filesystem="FAT32",
            size=123,
        )
        detector = UsbDetector(FakeProvider([[], [device], []]))

        self.assertEqual(detector.poll(), [])

        inserted = detector.poll()
        self.assertEqual(len(inserted), 1)
        self.assertEqual(inserted[0].event_type, "inserted")
        self.assertEqual(inserted[0].device, device)

        removed = detector.poll()
        self.assertEqual(len(removed), 1)
        self.assertEqual(removed[0].event_type, "removed")
        self.assertEqual(removed[0].device, device)

