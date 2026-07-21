"""
Unit tests for scripts/build_modules.py's title-matching and Winbindex-resolution
functions. Fixtures for _index_winbindex/resolve_pair are shaped exactly like a
real Winbindex by-filename document (confirmed via live fetches during
development), not guessed.

Run with:  python -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import build_modules as bm  # noqa: E402


class GuessModuleTests(unittest.TestCase):
    def test_matches_known_component(self):
        component, files = bm.guess_module("Windows Common Log File System Driver Elevation of Privilege Vulnerability")
        self.assertEqual(component, "Common Log File System Driver")
        self.assertIn("clfs.sys", files)

    def test_first_match_wins_specific_before_generic(self):
        # "Windows SMB Server..." matches both the specific "SMB Server" entry
        # ("smb server") and the generic "SMB" catch-all entry ("smb" is a
        # substring of "smb server" too) — list order must pick the specific one.
        component, files = bm.guess_module("Windows SMB Server Elevation of Privilege Vulnerability")
        self.assertEqual(component, "SMB Server")
        self.assertIn("srv2.sys", files)
        self.assertIn("srvnet.sys", files)

    def test_no_match_returns_none_and_empty_list(self):
        component, files = bm.guess_module("Some Totally Unmapped Component Vulnerability")
        self.assertIsNone(component)
        self.assertEqual(files, [])

    def test_case_insensitive(self):
        component, _files = bm.guess_module("WINDOWS KERNEL ELEVATION OF PRIVILEGE VULNERABILITY")
        self.assertEqual(component, "Windows Kernel")

    def test_extended_keyword_reuses_existing_binary_set(self):
        # Regression check for the 2026-07-17 COMPONENT_MAP expansion: "Windows
        # Digital Media" was added as an extra keyword on the existing "Windows
        # Media" entry rather than a new entry, and must resolve to the same files.
        component, files = bm.guess_module("Windows Digital Media Elevation of Privilege Vulnerability")
        self.assertEqual(component, "Windows Media")
        self.assertIn("mf.dll", files)

    def test_returned_files_list_is_a_copy(self):
        # guess_module returns list(files) specifically so callers can't mutate
        # the shared COMPONENT_MAP entry.
        _component, files = bm.guess_module("Win32k Elevation of Privilege Vulnerability")
        files.append("not-a-real-file.sys")
        _component2, files2 = bm.guess_module("Win32k Elevation of Privilege Vulnerability")
        self.assertNotIn("not-a-real-file.sys", files2)


class ResolveComponentTests(unittest.TestCase):
    """The ZDI-override + confidence-tier decision. Pure: no Winbindex network."""

    def _cve(self, title):
        return {"title": title, "fixes": []}

    def test_heuristic_specific_is_heuristic_confidence(self):
        comp, files, source, conf = bm.resolve_component(
            self._cve("Windows Common Log File System Driver Elevation of Privilege Vulnerability"))
        self.assertEqual((source, conf), ("heuristic", "heuristic"))
        self.assertEqual(files, ["clfs.sys"])

    def test_vague_kernel_guess_is_low_confidence(self):
        # "Windows Kernel ..." -> ntoskrnl.exe, the exact false-positive class:
        # ntoskrnl.exe changes every cumulative update so Winbindex can't disprove
        # the guess. With no advisory it must be flagged low.
        comp, files, source, conf = bm.resolve_component(
            self._cve("Windows Kernel Elevation of Privilege Vulnerability"))
        self.assertEqual(files, ["ntoskrnl.exe"])
        self.assertEqual((source, conf), ("heuristic", "low"))

    def test_zdi_files_override_the_title_guess(self):
        # ZDI says securekernel.exe; the vague-kernel ntoskrnl.exe guess is replaced.
        zdi = {"id": "ZDI-26-276", "url": "u", "component": "Secure Kernel",
               "files": ["securekernel.exe"]}
        comp, files, source, conf = bm.resolve_component(
            self._cve("Windows Kernel Elevation of Privilege Vulnerability"), zdi)
        self.assertEqual((comp, files, source, conf),
                         ("Secure Kernel", ["securekernel.exe"], "zdi", "advisory"))

    def test_zdi_provides_new_coverage_when_heuristic_empty(self):
        zdi = {"id": "ZDI-26-416", "url": "u", "component": "netvsc", "files": ["netvsc.sys"]}
        comp, files, source, conf = bm.resolve_component(
            self._cve("Some Totally Unmapped Component Vulnerability"), zdi)
        self.assertEqual((files, source, conf), (["netvsc.sys"], "zdi", "advisory"))

    def test_zdi_component_without_file_still_surfaces_advisory(self):
        # ServerManager isn't a Winbindex core binary -> no files, but the advisory
        # link should still be attachable (source=zdi, empty files).
        zdi = {"id": "ZDI-26-417", "url": "u", "component": "ServerManager", "files": []}
        comp, files, source, conf = bm.resolve_component(
            self._cve("Some Totally Unmapped Component Vulnerability"), zdi)
        self.assertEqual((comp, files, source), ("ServerManager", [], "zdi"))

    def test_nothing_matches_returns_none(self):
        self.assertIsNone(bm.resolve_component(self._cve("Some Totally Unmapped Component Vulnerability")))


class BuildEntryAdvisoryTests(unittest.TestCase):
    def test_advisory_only_entry_has_no_targets_but_keeps_link(self):
        # files=[] path never touches Winbindex, so this is network-free.
        cve = {"title": "Some Totally Unmapped Component Vulnerability", "fixes": []}
        zdi = {"id": "ZDI-26-417", "url": "https://z/ZDI-26-417/",
               "component": "ServerManager", "files": []}
        entry = bm.build_entry_for_cve(cve, zdi)
        self.assertEqual(entry["source"], "zdi")
        self.assertEqual(entry["files"], [])
        self.assertEqual(entry["targets"], [])
        self.assertEqual(entry["advisory"]["id"], "ZDI-26-417")
        self.assertEqual(entry["advisory"]["source"], "ZDI")

    def test_no_match_no_advisory_returns_none(self):
        cve = {"title": "Some Totally Unmapped Component Vulnerability", "fixes": []}
        self.assertIsNone(bm.build_entry_for_cve(cve, None))

    def test_advisory_ref_shape(self):
        self.assertIsNone(bm._advisory_ref(None))
        ref = bm._advisory_ref({"id": "ZDI-26-1", "url": "u", "component": "X"})
        self.assertEqual(ref, {"source": "ZDI", "id": "ZDI-26-1", "url": "u", "component": "X"})


def _wb_entry(sha256, timestamp, virtual_size, version, machine_type, windows_versions):
    return {
        "fileInfo": {
            "sha256": sha256,
            "timestamp": timestamp,
            "virtualSize": virtual_size,
            "version": version,
            "machineType": machine_type,
        },
        "windowsVersions": windows_versions,
    }


class IndexWinbindexTests(unittest.TestCase):
    def test_builds_by_target_chain_sorted_ascending(self):
        data = {
            "sha_new": _wb_entry("sha_new", 1000, 500, "10.0.22621.7219 (WinBuild)", 0x8664,
                                  {"11-23H2": {"KB5093998": {}}}),
            "sha_old": _wb_entry("sha_old", 999, 499, "10.0.22621.7079 (WinBuild)", 0x8664,
                                  {"11-23H2": {"KB5087420": {}}}),
        }
        idx = bm._index_winbindex(data)
        chain = idx["by_target"][("11-23H2", "x64")]
        self.assertEqual([b["rev"] for b in chain], [7079, 7219])  # ascending

    def test_id_count_spans_all_architectures(self):
        # The symbol-server URL doesn't encode arch, so a collision on x64 and one
        # on arm64 with the same (timestamp, size) must be counted together.
        data = {
            "a": _wb_entry("a", 1000, 500, "10.0.22621.100 (WinBuild)", 0x8664, {}),
            "b": _wb_entry("b", 1000, 500, "10.0.22621.200 (WinBuild)", 0xAA64, {}),
        }
        idx = bm._index_winbindex(data)
        sym_id = bm._sym_id(1000, 500)
        self.assertEqual(idx["id_count"][sym_id], 2)

    def test_non_windows_10_version_string_skipped(self):
        data = {"a": _wb_entry("a", 1000, 500, "1.2.3.4", 0x8664, {"11-23H2": {"KB1": {}}})}
        idx = bm._index_winbindex(data)
        self.assertEqual(idx["by_target"], {})

    def test_missing_timestamp_or_virtualsize_skipped_entirely(self):
        data = {"a": {"fileInfo": {"version": "10.0.22621.100 (WinBuild)", "machineType": 0x8664},
                       "windowsVersions": {"11-23H2": {"KB1": {}}}}}
        idx = bm._index_winbindex(data)
        self.assertEqual(idx["by_target"], {})
        self.assertEqual(idx["id_count"], {})


class ResolvePairTests(unittest.TestCase):
    def _wb(self):
        data = {
            "sha_base": _wb_entry("sha_base", 100, 100, "10.0.22621.2428 (WinBuild)", 0x8664,
                                   {"11-23H2": {"BASE": {}}}),
            "sha_old": _wb_entry("sha_old", 200, 200, "10.0.22621.7079 (WinBuild)", 0x8664,
                                  {"11-23H2": {"KB5087420": {}}}),
            "sha_new": _wb_entry("sha_new", 300, 300, "10.0.22621.7219 (WinBuild)", 0x8664,
                                  {"11-23H2": {"KB5093998": {}}}),
        }
        return bm._index_winbindex(data)

    def test_finds_patched_and_immediate_predecessor(self):
        wb = self._wb()
        patched, unpatched = bm.resolve_pair(wb, "11-23H2", "x64", "KB5093998")
        self.assertEqual(patched["rev"], 7219)
        self.assertEqual(unpatched["rev"], 7079)

    def test_kb_not_found_returns_none(self):
        wb = self._wb()
        self.assertIsNone(bm.resolve_pair(wb, "11-23H2", "x64", "KB9999999"))

    def test_unknown_target_returns_none(self):
        wb = self._wb()
        self.assertIsNone(bm.resolve_pair(wb, "10-99H9", "x64", "KB5093998"))

    def test_earliest_build_has_no_predecessor(self):
        wb = self._wb()
        patched, unpatched = bm.resolve_pair(wb, "11-23H2", "x64", "BASE")
        self.assertEqual(patched["rev"], 2428)
        self.assertIsNone(unpatched)


if __name__ == "__main__":
    unittest.main()
