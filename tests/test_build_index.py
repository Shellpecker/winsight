"""
Unit tests for scripts/build_index.py's CVRF-parsing functions.

These target the specific spots that have actually broken this project before:
CVRF v3 dropping the KBArticle element, CWE sometimes being a list instead of a
dict, and the exploited-flag logic needing to filter Threats by Type. Fixtures
are shaped exactly like the real MSRC CVRF v3 API responses (confirmed via live
API calls during development), not guessed shapes.

Run with:  python -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import build_index as bi  # noqa: E402


class KbIdsFromRemediationsTests(unittest.TestCase):
    def test_bare_digit_description(self):
        vuln = {"Remediations": [{"Description": {"Value": "5060531"}, "URL": ""}]}
        self.assertEqual(bi.kb_ids_from_remediations(vuln), {"KB5060531"})

    def test_kb_from_url_query_param(self):
        vuln = {"Remediations": [{
            "Description": {"Value": "Security Update"},
            "URL": "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5060531",
        }]}
        self.assertEqual(bi.kb_ids_from_remediations(vuln), {"KB5060531"})

    def test_dedups_when_both_sources_agree(self):
        vuln = {"Remediations": [{
            "Description": {"Value": "5060531"},
            "URL": "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5060531",
        }]}
        self.assertEqual(bi.kb_ids_from_remediations(vuln), {"KB5060531"})

    def test_multiple_remediations_multiple_kbs(self):
        vuln = {"Remediations": [
            {"Description": {"Value": "5060531"}, "URL": ""},
            {"Description": {"Value": "5060532"}, "URL": ""},
        ]}
        self.assertEqual(bi.kb_ids_from_remediations(vuln), {"KB5060531", "KB5060532"})

    def test_non_numeric_description_ignored(self):
        vuln = {"Remediations": [{"Description": {"Value": "Restart the computer"}, "URL": ""}]}
        self.assertEqual(bi.kb_ids_from_remediations(vuln), set())

    def test_no_remediations(self):
        self.assertEqual(bi.kb_ids_from_remediations({}), set())
        self.assertEqual(bi.kb_ids_from_remediations({"Remediations": None}), set())


class ExtractCweTests(unittest.TestCase):
    def test_dict_form(self):
        vuln = {"CWE": {"ID": "CWE-122", "Value": "Heap-based Buffer Overflow"}}
        self.assertEqual(bi.extract_cwe(vuln), {"id": "CWE-122", "name": "Heap-based Buffer Overflow"})

    def test_list_form_takes_first(self):
        # CVRF v3 sometimes assigns multiple CWEs; this crashed the build before
        # the isinstance(cwe, list) check was added ('list' has no .get()).
        vuln = {"CWE": [
            {"ID": "CWE-416", "Value": "Use After Free"},
            {"ID": "CWE-822", "Value": "Untrusted Pointer Dereference"},
        ]}
        self.assertEqual(bi.extract_cwe(vuln), {"id": "CWE-416", "name": "Use After Free"})

    def test_empty_list_returns_none(self):
        self.assertIsNone(bi.extract_cwe({"CWE": []}))

    def test_missing_cwe_returns_none(self):
        self.assertIsNone(bi.extract_cwe({}))

    def test_empty_id_returns_none(self):
        self.assertIsNone(bi.extract_cwe({"CWE": {"ID": "", "Value": "x"}}))


class ExtractVectorTests(unittest.TestCase):
    def test_returns_full_vector_string(self):
        vuln = {"CVSSScoreSets": [{"BaseScore": 7.8,
                "Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"}]}
        self.assertEqual(bi.extract_vector(vuln), "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H")

    def test_no_score_sets_returns_none(self):
        self.assertIsNone(bi.extract_vector({}))
        self.assertIsNone(bi.extract_vector({"CVSSScoreSets": []}))

    def test_empty_vector_returns_none(self):
        self.assertIsNone(bi.extract_vector({"CVSSScoreSets": [{"BaseScore": 5.0, "Vector": ""}]}))
        self.assertIsNone(bi.extract_vector({"CVSSScoreSets": [{"BaseScore": 5.0}]}))


class ExtractExploitedTests(unittest.TestCase):
    def test_exploited_and_disclosed_yes(self):
        vuln = {"Threats": [{"Type": 1, "Description": {
            "Value": "Publicly Disclosed:Yes;Exploited:Yes;Latest Software Release:Exploitation Detected"
        }}]}
        exploited, disclosed, assessment = bi.extract_exploited(vuln)
        self.assertTrue(exploited)
        self.assertTrue(disclosed)
        self.assertEqual(assessment, "Exploitation Detected")

    def test_non_exploitstatus_threat_types_ignored(self):
        # Type=0 (Severity) and Type=3 (Impact) share the Threats array but never
        # carry exploitation data. Reading them unconditionally was the bug that
        # caused false-positive "Exploited" flags.
        vuln = {"Threats": [
            {"Type": 0, "Description": {"Value": "Critical"}},
            {"Type": 3, "Description": {"Value": "Exploited:Yes"}},  # decoy on wrong Type
        ]}
        exploited, disclosed, assessment = bi.extract_exploited(vuln)
        self.assertFalse(exploited)
        self.assertFalse(disclosed)
        self.assertIsNone(assessment)

    def test_exploited_no_is_default_not_flagged(self):
        vuln = {"Threats": [{"Type": 1, "Description": {
            "Value": "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely"
        }}]}
        exploited, disclosed, assessment = bi.extract_exploited(vuln)
        self.assertFalse(exploited)
        self.assertFalse(disclosed)
        self.assertEqual(assessment, "Exploitation Less Likely")

    def test_assessment_keeps_highest_priority_across_multiple_entries(self):
        # MSRC emits one Type=1 entry per affected product; different products can
        # carry different assessments. We must keep the worst (highest-priority) one.
        vuln = {"Threats": [
            {"Type": 1, "Description": {"Value": "Exploited:No;Latest Software Release:Exploitation Unlikely"}},
            {"Type": 1, "Description": {"Value": "Exploited:No;Latest Software Release:Exploitation More Likely"}},
        ]}
        _, _, assessment = bi.extract_exploited(vuln)
        self.assertEqual(assessment, "Exploitation More Likely")

    def test_no_threats(self):
        exploited, disclosed, assessment = bi.extract_exploited({})
        self.assertFalse(exploited)
        self.assertFalse(disclosed)
        self.assertIsNone(assessment)


class ParseProductTargetTests(unittest.TestCase):
    def test_windows_11_x64(self):
        winver, arch = bi.parse_product_target("Windows 11 Version 23H2 for x64-based Systems")
        self.assertEqual((winver, arch), ("11-23H2", "x64"))

    def test_windows_10_arm64(self):
        winver, arch = bi.parse_product_target("Windows 10 Version 22H2 for ARM64-based Systems")
        self.assertEqual((winver, arch), ("22H2", "arm64"))

    def test_server_2016_maps_to_1607(self):
        winver, arch = bi.parse_product_target("Windows Server 2016")
        self.assertEqual((winver, arch), ("1607", "x64"))

    def test_server_2019_maps_to_1809(self):
        winver, arch = bi.parse_product_target("Windows Server 2019 (Server Core installation)")
        self.assertEqual((winver, arch), ("1809", "x64"))

    def test_server_2022_is_unmappable(self):
        # No Winbindex key exists for 2022/2025/2012 — must stay None, not guess wrong.
        winver, arch = bi.parse_product_target("Windows Server 2022")
        self.assertIsNone(winver)

    def test_unrecognized_product_label(self):
        winver, arch = bi.parse_product_target(".NET Framework 4.8")
        self.assertIsNone(winver)


class ExtractFixesTests(unittest.TestCase):
    def _vuln(self, remediations):
        return {"Remediations": remediations}

    def test_only_type_2_remediations_counted(self):
        product_labels = {"P1": "Windows 11 Version 23H2 for x64-based Systems"}
        vuln = self._vuln([
            {"Type": 1, "Description": {"Value": "5060531"}, "ProductID": ["P1"]},  # not a Vendor Fix
            {"Type": 2, "Description": {"Value": "5060532"}, "ProductID": ["P1"]},
        ])
        fixes = bi.extract_fixes(vuln, product_labels)
        self.assertEqual(len(fixes), 1)
        self.assertEqual(fixes[0]["kb"], "KB5060532")
        self.assertEqual(fixes[0]["winver"], "11-23H2")

    def test_server_products_dropped(self):
        product_labels = {"P1": "Windows Server 2022"}
        vuln = self._vuln([{"Type": 2, "Description": {"Value": "5060531"}, "ProductID": ["P1"]}])
        self.assertEqual(bi.extract_fixes(vuln, product_labels), [])

    def test_dedups_same_kb_winver_arch(self):
        product_labels = {
            "P1": "Windows 11 Version 23H2 for x64-based Systems",
            "P2": "Windows 11 Version 23H2 for x64-based Systems (Server Core installation)",
        }
        vuln = self._vuln([{"Type": 2, "Description": {"Value": "5060531"}, "ProductID": ["P1", "P2"]}])
        fixes = bi.extract_fixes(vuln, product_labels)
        self.assertEqual(len(fixes), 1)

    def test_unknown_product_id_skipped(self):
        vuln = self._vuln([{"Type": 2, "Description": {"Value": "5060531"}, "ProductID": ["UNKNOWN"]}])
        self.assertEqual(bi.extract_fixes(vuln, {}), [])


class NormalizeVersionLabelTests(unittest.TestCase):
    def test_strips_arch_and_version_word(self):
        self.assertEqual(
            bi.normalize_version_label("Windows 11 Version 23H2 for x64-based Systems"),
            "Windows 11 23H2",
        )

    def test_strips_parenthetical_install_type(self):
        self.assertEqual(
            bi.normalize_version_label("Windows Server 2022 (Server Core installation)"),
            "Windows Server 2022",
        )


class ClassifyImpactTests(unittest.TestCase):
    def test_known_categories(self):
        cases = {
            "Windows Kernel Remote Code Execution Vulnerability": "rce",
            "Windows Kernel Elevation of Privilege Vulnerability": "eop",
            "Windows Kernel Denial of Service Vulnerability": "dos",
            "Windows Kernel Spoofing Vulnerability": "spoofing",
            "Windows Kernel Information Disclosure Vulnerability": "info",
            "Windows Kernel Security Feature Bypass Vulnerability": "bypass",
            "Windows Kernel Tampering Vulnerability": "tamper",
        }
        for title, expected in cases.items():
            self.assertEqual(bi.classify_impact(title, {}), expected, msg=title)

    def test_unrecognized_falls_back_to_other(self):
        self.assertEqual(bi.classify_impact("Something Else Entirely", {}), "other")


class IsWindowsCveTests(unittest.TestCase):
    def test_windows_version_present(self):
        self.assertTrue(bi.is_windows_cve(["Windows 11 23H2"], []))

    def test_only_non_windows_versions(self):
        self.assertFalse(bi.is_windows_cve([".NET 8.0", "Azure DevOps"], []))

    def test_empty_versions(self):
        self.assertFalse(bi.is_windows_cve([], []))


if __name__ == "__main__":
    unittest.main()
