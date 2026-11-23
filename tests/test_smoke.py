import tempfile
import unittest
from pathlib import Path

from main import inventory_processes, redact_command_line


class ProcessWatchtowerTests(unittest.TestCase):
    def make_proc(self, root: Path, pid: int, name: str, cmdline: bytes = b"/usr/bin/demo\x00--mode\x00safe"):
        proc = root / str(pid)
        proc.mkdir()
        (proc / "comm").write_text(name, encoding="utf-8")
        (proc / "stat").write_text(f"{pid} ({name}) S 1 0 0 0 0 0", encoding="utf-8")
        (proc / "status").write_text("Name:\tdemo\nUid:\t1000\t1000\t1000\t1000\n", encoding="utf-8")
        (proc / "cmdline").write_bytes(cmdline)

    def test_inventory_reads_process_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_proc(root, 123, "demo")
            report = inventory_processes(root)
            self.assertEqual(report["process_count"], 1)
            self.assertEqual(report["processes"][0]["pid"], 123)
            self.assertEqual(report["processes"][0]["uid"], 1000)

    def test_allowlist_flags_unlisted_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_proc(root, 123, "unexpected")
            report = inventory_processes(root, {"sshd", "systemd"})
            self.assertEqual(report["not_in_allowlist_count"], 1)
            self.assertTrue(report["processes"][0]["not_in_allowlist"])

    def test_command_line_redacts_common_secret_assignment(self):
        rendered = redact_command_line(b"worker\x00API_KEY=abc123\x00--safe\x00")
        self.assertIn("API_KEY=[REDACTED]", rendered)
        self.assertNotIn("abc123", rendered)

    def test_non_proc_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "file"
            file_path.write_text("x", encoding="utf-8")
            with self.assertRaises(FileNotFoundError):
                inventory_processes(file_path)


if __name__ == "__main__":
    unittest.main()
