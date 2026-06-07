"""
Unit tests for tool parsers.
Run without SIFT tools installed — uses synthetic output to test parsing logic.
"""
import unittest
from unittest.mock import patch, MagicMock
from mcp_server.tools.memory import _parse_vol_tsv, analyze_processes, analyze_network
from mcp_server.tools.artifacts import _parse_regripper_output, _check_prefetch_suspicious
from mcp_server.models import PrefetchEntry, Confidence


MOCK_PSLIST = """Volatility 3 Framework 2.5.0
Progress: 100.00\tPDB scanning finished
PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tSessionId\tWow64\tCreateTime\tExitTime\tFile output
4\t0\tSystem\t0x8a0af040\t98\t-\tN/A\tFalse\t2024-01-15 08:00:00\tN/A\tDisabled
1234\t4\texplorer.exe\t0x9b1bf050\t42\t800\t1\tFalse\t2024-01-15 08:05:00\tN/A\tDisabled
5678\t1234\tmimikatz.exe\t0x9c2cf060\t3\t100\t1\tFalse\t2024-01-15 10:23:00\tN/A\tDisabled
9999\t1234\tsvchost.exe\t0x9d3df070\t8\t200\t1\tFalse\t2024-01-15 09:00:00\tN/A\tDisabled
"""

MOCK_NETSCAN = """Volatility 3 Framework 2.5.0
Progress: 100.00\tPDB scanning finished
Offset\tProto\tLocalAddr\tLocalPort\tForeignAddr\tForeignPort\tState\tPID\tOwner\tCreated
0x1234\tTCPv4\t192.168.1.100:49200\t49200\t198.51.100.50:4444\t4444\tESTABLISHED\t5678\tmimikatz.exe\t2024-01-15 10:23:05
0x5678\tTCPv4\t192.168.1.100:49100\t49100\t192.168.1.1:80\t80\tESTABLISHED\t1234\texplorer.exe\t2024-01-15 08:05:10
"""

MOCK_REGRIPPER_RUN = """
Software\\Microsoft\\Windows\\CurrentVersion\\Run
  backdoor = C:\\Users\\Public\\update.exe
  OneDrive = C:\\Program Files\\OneDrive\\OneDrive.exe
"""


class TestPSListParsing(unittest.TestCase):
    def test_parses_process_entries(self):
        rows = _parse_vol_tsv(MOCK_PSLIST)
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["ImageFileName"], "System")
        self.assertEqual(rows[0]["PID"], "4")

    @patch("mcp_server.tools.memory._run_vol")
    def test_detects_mimikatz(self, mock_vol):
        mock_vol.return_value = (MOCK_PSLIST, None)
        processes, findings = analyze_processes("/fake/memory.raw")
        malicious = [f for f in findings if "mimikatz" in f.description.lower()]
        self.assertTrue(len(malicious) > 0, "Should detect mimikatz.exe")

    @patch("mcp_server.tools.memory._run_vol")
    def test_handles_vol_error(self, mock_vol):
        mock_vol.return_value = ("", "vol not found")
        processes, findings = analyze_processes("/fake/memory.raw")
        self.assertEqual(len(processes), 0)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "tool_error")


class TestNetScanParsing(unittest.TestCase):
    @patch("mcp_server.tools.memory._run_vol")
    def test_detects_external_connection(self, mock_vol):
        mock_vol.return_value = (MOCK_NETSCAN, None)
        connections, findings = analyze_network("/fake/memory.raw")
        external = [f for f in findings if f.category == "external_connection"]
        self.assertEqual(len(external), 1)
        self.assertIn("198.51.100.50", external[0].description)

    @patch("mcp_server.tools.memory._run_vol")
    def test_ignores_private_connections(self, mock_vol):
        mock_vol.return_value = (MOCK_NETSCAN, None)
        _, findings = analyze_network("/fake/memory.raw")
        # 192.168.1.1 is private — should NOT be flagged
        private_flags = [f for f in findings if "192.168.1.1" in f.description]
        self.assertEqual(len(private_flags), 0)


class TestRegistryParsing(unittest.TestCase):
    def test_flags_suspicious_autorun(self):
        findings = _parse_regripper_output(MOCK_REGRIPPER_RUN, "run")
        suspicious = [r for r in findings if r.suspicious]
        self.assertTrue(len(suspicious) > 0)
        self.assertTrue(any("update.exe" in (r.data or "") for r in suspicious))

    def test_allows_known_good(self):
        findings = _parse_regripper_output(MOCK_REGRIPPER_RUN, "run")
        onedrive = [r for r in findings if "OneDrive" in (r.data or "")]
        # OneDrive in Program Files should not be flagged
        self.assertTrue(all(not r.suspicious for r in onedrive))


class TestPrefetchChecks(unittest.TestCase):
    def test_flags_known_malicious(self):
        entry = PrefetchEntry(executable="MIMIKATZ.EXE", run_count=3, last_run=None, path="C:\\Windows\\Temp\\MIMIKATZ.EXE-ABC.pf")
        findings = []
        _check_prefetch_suspicious(entry, findings)
        self.assertTrue(entry.suspicious)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].confidence, Confidence.HIGH)

    def test_flags_suspicious_path(self):
        entry = PrefetchEntry(executable="UPDATE.EXE", run_count=1, last_run=None, path="C:\\Users\\Public\\update.exe")
        findings = []
        _check_prefetch_suspicious(entry, findings)
        self.assertTrue(entry.suspicious)

    def test_allows_system_binaries(self):
        entry = PrefetchEntry(executable="NOTEPAD.EXE", run_count=5, last_run=None, path="C:\\Windows\\System32\\notepad.exe")
        findings = []
        _check_prefetch_suspicious(entry, findings)
        self.assertFalse(entry.suspicious)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
