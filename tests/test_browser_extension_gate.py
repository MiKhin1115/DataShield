import json
from pathlib import Path
from unittest import TestCase


class BrowserExtensionGateTests(TestCase):
    def test_file_input_is_stopped_before_async_scan_and_replayed_only_if_clean(self) -> None:
        script = Path("dlp_agent/browser_extension/content.js").read_text(encoding="utf-8")
        gate = script.split('document.addEventListener("change"', 1)[1].split(
            "// 4. Apply the same", 1
        )[0]

        self.assertIn("files.every(file => file.size === 0)", gate)
        self.assertIn("allowEmptyFilesWithoutReplay", gate)
        self.assertLess(gate.index("files.every(file => file.size === 0)"), gate.index("e.preventDefault()"))
        self.assertIn("e.preventDefault()", gate)
        self.assertIn("e.stopImmediatePropagation()", gate)
        self.assertIn('input.value = ""', gate)
        self.assertIn("inspectFiles(files)", gate)
        self.assertIn("if (result.blocked)", gate)
        self.assertIn('input.dispatchEvent(new Event("change"', gate)
        self.assertLess(gate.index("e.stopImmediatePropagation()"), gate.index("inspectFiles(files)"))
        self.assertLess(gate.index("releaseActiveScan()"), gate.index('input.dispatchEvent(new Event("change"'))
        self.assertNotIn(".finally(() =>", gate)

    def test_drag_drop_is_held_until_scan_passes(self) -> None:
        script = Path("dlp_agent/browser_extension/content.js").read_text(encoding="utf-8")
        drop_gate = script.split('document.addEventListener("drop"', 1)[1].split(
            "// Surface Google Drive", 1
        )[0]

        self.assertIn("files.every(file => file.size === 0)", drop_gate)
        self.assertIn("allowEmptyFilesWithoutReplay", drop_gate)
        self.assertLess(drop_gate.index("files.every(file => file.size === 0)"), drop_gate.index("e.preventDefault()"))
        self.assertIn("e.preventDefault()", drop_gate)
        self.assertIn("e.stopImmediatePropagation()", drop_gate)
        self.assertIn("if (result.blocked)", drop_gate)
        self.assertIn('dropTarget.dispatchEvent(new DragEvent("drop"', drop_gate)
        self.assertLess(drop_gate.index("releaseActiveScan()"), drop_gate.index('dropTarget.dispatchEvent(new DragEvent("drop"'))

    def test_manifest_version_is_bumped_for_extension_reload(self) -> None:
        manifest = json.loads(
            Path("dlp_agent/browser_extension/manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["version"], "1.8")

    def test_clean_scan_result_is_cached_for_the_telegram_network_request(self) -> None:
        script = Path("dlp_agent/browser_extension/content.js").read_text(encoding="utf-8")

        self.assertIn("const cleanScanCache = new WeakMap()", script)
        self.assertIn("const cachedScan = cleanScanCache.get(file)", script)
        self.assertIn("cleanScanCache.set(file", script)

    def test_large_scans_are_relayed_to_the_worker_in_bounded_chunks(self) -> None:
        bridge = Path("dlp_agent/browser_extension/bridge.js").read_text(encoding="utf-8")
        background = Path("dlp_agent/browser_extension/background.js").read_text(encoding="utf-8")

        self.assertIn('type: "SCAN_FILE_START"', bridge)
        self.assertIn('type: "SCAN_FILE_CHUNK"', bridge)
        self.assertIn('type: "SCAN_FILE_FINISH"', bridge)
        self.assertIn("SCAN_CHUNK_BYTES = 256 * 1024", bridge)
        self.assertIn('message.type === "SCAN_FILE_START"', background)
        self.assertIn('message.type === "SCAN_FILE_CHUNK"', background)
        self.assertIn('message.type === "SCAN_FILE_FINISH"', background)
        self.assertIn("finishChunkedScan", background)
