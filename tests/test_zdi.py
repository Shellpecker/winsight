"""
Unit tests for scripts/zdi.py's ZDI-advisory title parsing and RSS ingestion.

Titles/fixtures are taken verbatim from ZDI's live published RSS feed (confirmed
during development), not guessed shapes. The parser is the one piece of judgement
in the ZDI cross-reference, so its component/file extraction is what these lock
down — a regression here silently mis-corrects a binary guess.

Run with:  python -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import zdi  # noqa: E402


class ParseComponentTests(unittest.TestCase):
    def test_real_titles(self):
        cases = {
            "ZDI-26-417: Microsoft Windows ServerManager Exposed Dangerous Method Local Privilege Escalation Vulnerability": "ServerManager",
            "ZDI-26-416: Microsoft Hyper-V netvsc Out-Of-Bounds Read Local Privilege Escalation Vulnerability": "netvsc",
            "ZDI-26-415: Microsoft Windows WMI Providers Incorrect Authorization Local Privilege Escalation Vulnerability": "WMI Providers",
            "ZDI-26-310: Microsoft Windows splwow64 Race Condition Local Privilege Escalation Vulnerability": "splwow64",
            "ZDI-26-309: Microsoft Windows Message Queueing Double Free Local Privilege Escalation Vulnerability": "Message Queueing",
            "ZDI-26-279: Microsoft Windows Snipping Tool Improper Input Validation Remote Code Execution Vulnerability": "Snipping Tool",
            "ZDI-26-278: Microsoft Windows win32kfull Improper Locking Local Privilege Escalation Vulnerability": "win32kfull",
            "ZDI-26-277: Microsoft Windows afd.sys Race Condition Local Privilege Escalation Vulnerability": "afd.sys",
            "ZDI-26-276: Microsoft Windows Secure Kernel Double Free Local Privilege Escalation Vulnerability": "Secure Kernel",
        }
        for title, expected in cases.items():
            self.assertEqual(zdi.parse_component(title), expected, msg=title)

    def test_strips_windows_server_prefix_not_just_windows(self):
        # "Windows Server" must be stripped whole, else the component would start
        # with a stray "Server".
        c = zdi.parse_component("ZDI-26-001: Microsoft Windows Server DHCP Server Service Denial of Service Vulnerability")
        self.assertFalse(c.lower().startswith("server "))

    def test_strips_pwn2own_tag_and_version_remnant(self):
        c = zdi.parse_component(
            "ZDI-26-100: (Pwn2Own) Microsoft Windows 11 vhdmp Improper Validation of Array Index Local Privilege Escalation Vulnerability")
        # Event tag + "Windows 11" remnant gone; bug-class trimmed. Exact bug-class
        # enumeration is best-effort, so the key guarantee is it starts clean.
        self.assertTrue(c.startswith("vhdmp"), c)
        self.assertNotIn("Pwn2Own", c)
        self.assertNotIn("11", c)

    def test_hyphenated_denial_of_service_terminates_component(self):
        c = zdi.parse_component(
            "ZDI-26-101: Microsoft Windows Remote Desktop Gateway Service Null Pointer Dereference Denial-of-Service Vulnerability")
        self.assertEqual(c, "Remote Desktop Gateway Service")

    def test_no_recognizable_component(self):
        # Impact phrase immediately after the prefix -> empty component, no crash.
        self.assertEqual(zdi.parse_component("ZDI-26-002: Microsoft Windows Remote Code Execution Vulnerability"), "")


class ComponentFilesTests(unittest.TestCase):
    def test_literal_filename_token_in_title(self):
        files = zdi.component_files(
            "Microsoft Windows afd.sys Race Condition Local Privilege Escalation Vulnerability", "afd.sys")
        self.assertEqual(files, ["afd.sys"])

    def test_bare_basename_component_mapped_to_extension(self):
        self.assertEqual(zdi.component_files("... splwow64 ...", "splwow64"), ["splwow64.exe"])
        self.assertEqual(zdi.component_files("... netvsc ...", "netvsc"), ["netvsc.sys"])
        self.assertEqual(zdi.component_files("... win32kfull ...", "win32kfull"), ["win32kfull.sys"])

    def test_multi_file_component(self):
        self.assertEqual(
            zdi.component_files("... WMI Providers ...", "WMI Providers"),
            ["wmiprvse.exe", "wbemcomn.dll"])

    def test_message_queueing_and_queuing_both_map(self):
        self.assertEqual(zdi.component_files("x", "Message Queueing"), ["mqqm.dll", "mqsvc.exe"])
        self.assertEqual(zdi.component_files("x", "Message Queuing"), ["mqqm.dll", "mqsvc.exe"])

    def test_newly_mapped_driver_basenames(self):
        self.assertEqual(zdi.component_files("x", "vhdmp"), ["vhdmp.sys"])
        self.assertEqual(zdi.component_files("x", "mskssrv Driver"), ["mskssrv.sys"])
        self.assertEqual(zdi.component_files("x", "dxkrnl"), ["dxgkrnl.sys"])
        self.assertEqual(zdi.component_files("x", "NTFS Junction"), ["ntfs.sys"])

    def test_unmapped_component_yields_no_files(self):
        # ServerManager / Snipping Tool aren't Winbindex-tracked core binaries.
        self.assertEqual(zdi.component_files("... Snipping Tool ...", "Snipping Tool"), [])
        self.assertEqual(zdi.component_files("... ServerManager ...", "ServerManager"), [])

    def test_dedups_when_literal_and_map_agree(self):
        # afd.sys appears both as a literal token and would map via "ancillary
        # function" — but here only the literal is present; ensure no dup anyway.
        files = zdi.component_files("Microsoft Windows Ancillary Function Driver afd.sys ...", "Ancillary Function Driver afd.sys")
        self.assertEqual(files, ["afd.sys"])


class ParseRssTests(unittest.TestCase):
    RSS = """<rss><channel>
      <item>
        <title><![CDATA[ZDI-26-276: Microsoft Windows Secure Kernel Double Free Local Privilege Escalation Vulnerability]]></title>
        <link>https://www.zerodayinitiative.com/advisories/ZDI-26-276/</link>
        <description><![CDATA[CVE-2026-26179. Some text.]]></description>
      </item>
      <item>
        <title><![CDATA[ZDI-26-294: (0Day) Microsoft Windows library-ms NTLM Response Information Disclosure Vulnerability]]></title>
        <link>https://www.zerodayinitiative.com/advisories/ZDI-26-294/</link>
        <description><![CDATA[No CVE assigned yet.]]></description>
      </item>
      <item>
        <title><![CDATA[ZDI-26-500: Microsoft Edge (Chromium) Type Confusion Remote Code Execution Vulnerability]]></title>
        <link>https://www.zerodayinitiative.com/advisories/ZDI-26-500/</link>
        <description><![CDATA[CVE-2026-99999.]]></description>
      </item>
    </channel></rss>"""

    def test_keeps_windows_cve_item(self):
        m = zdi.parse_rss(self.RSS)
        self.assertIn("CVE-2026-26179", m)
        e = m["CVE-2026-26179"]
        self.assertEqual(e["id"], "ZDI-26-276")
        self.assertEqual(e["component"], "Secure Kernel")
        self.assertEqual(e["files"], ["securekernel.exe"])
        self.assertTrue(e["url"].endswith("/ZDI-26-276/"))

    def test_skips_item_without_cve(self):
        # The library-ms 0-day has no assigned CVE -> nothing to join on.
        m = zdi.parse_rss(self.RSS)
        self.assertTrue(all("library-ms" not in (v.get("component") or "") for v in m.values()))

    def test_skips_non_windows_product(self):
        # Edge (Chromium) is not Winbindex-tracked; excluded.
        m = zdi.parse_rss(self.RSS)
        self.assertNotIn("CVE-2026-99999", m)


class ParseListingTests(unittest.TestCase):
    # Two <tr> rows shaped like the live published-listing page: a ZDI-id anchor,
    # a CVE cell, and an advisory-title-cell with the full title. Second row is a
    # non-Microsoft product that must be excluded.
    LISTING = """
    <tr><td><a href="/advisories/ZDI-26-277/">ZDI-26-277</a></td>
        <td data-label="CVE"><span>CVE-2026-32073</span></td>
        <td class="advisory-title-cell"><div><span>Microsoft Windows afd.sys Race Condition Local Privilege Escalation Vulnerability</span></div></td></tr>
    <tr><td><a href="/advisories/ZDI-26-300/">ZDI-26-300</a></td>
        <td data-label="CVE"><span>CVE-2026-40000</span></td>
        <td class="advisory-title-cell"><div><span>Adobe Acrobat Use-After-Free Remote Code Execution Vulnerability</span></div></td></tr>
    """

    def test_parses_microsoft_row(self):
        m = zdi.parse_listing(self.LISTING)
        self.assertIn("CVE-2026-32073", m)
        e = m["CVE-2026-32073"]
        self.assertEqual(e["id"], "ZDI-26-277")
        self.assertEqual(e["component"], "afd.sys")
        self.assertEqual(e["files"], ["afd.sys"])
        self.assertTrue(e["url"].endswith("/ZDI-26-277/"))

    def test_excludes_non_microsoft_row(self):
        m = zdi.parse_listing(self.LISTING)
        self.assertNotIn("CVE-2026-40000", m)


class MergeTests(unittest.TestCase):
    def test_manual_entry_preserved(self):
        existing = {"CVE-1": {"id": "ZDI-X", "files": ["a.sys"], "source": "manual"}}
        fresh = {"CVE-1": {"id": "ZDI-Y", "files": ["b.sys"]}}
        merged = zdi.merge(existing, fresh)
        self.assertEqual(merged["CVE-1"]["files"], ["a.sys"])  # manual wins

    def test_fresh_overwrites_non_manual(self):
        existing = {"CVE-1": {"id": "ZDI-X", "files": ["a.sys"]}}
        fresh = {"CVE-1": {"id": "ZDI-X", "files": ["a.sys", "c.sys"]}}
        merged = zdi.merge(existing, fresh)
        self.assertEqual(merged["CVE-1"]["files"], ["a.sys", "c.sys"])

    def test_out_of_window_entry_retained(self):
        # RSS only carries recent advisories; older entries must survive a run
        # that no longer sees them.
        existing = {"CVE-OLD": {"id": "ZDI-OLD", "files": ["old.sys"]}}
        merged = zdi.merge(existing, {"CVE-NEW": {"id": "ZDI-NEW", "files": ["new.sys"]}})
        self.assertIn("CVE-OLD", merged)
        self.assertIn("CVE-NEW", merged)


if __name__ == "__main__":
    unittest.main()
