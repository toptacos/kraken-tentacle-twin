#!/usr/bin/env python3
import json, os, subprocess, tempfile, unittest, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def invoke(action, payload=None, env=None):
    run = os.environ.copy()
    run["KRAKEN_OFFLINE"] = "1"
    if env:
        run.update(env)
    proc = subprocess.run(
        ["python3", str(ROOT / "handler.py")],
        input=json.dumps({"v": 1, "action": action, "payload": payload or {}}),
        text=True, capture_output=True, env=run, check=False,
    )
    return json.loads([ln for ln in proc.stdout.splitlines() if ln.startswith("{")][-1])


class Twin(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.env = {"KRAKEN_HOME": str(self.home)}
        self.drive = self.home / "drive"
        self.drive.mkdir()

    def test_ping_brand(self):
        b = invoke("ping", env=self.env)
        self.assertEqual(b["result"]["arm"], "twin")
        self.assertEqual(b["result"]["brand"], "TopTaco")
        self.assertIn("tentacles", b["result"]["tagline"])

    def test_unknown(self):
        self.assertEqual(invoke("wipe", env=self.env)["error"]["code"], "unknown_action")

    def test_missing_drives(self):
        self.assertEqual(invoke("scan", env=self.env)["error"]["code"], "missing")

    def test_exact_duplicates(self):
        a = self.drive / "a.txt"
        b = self.drive / "sub"
        b.mkdir()
        a.write_text("same-bytes")
        (b / "copy.txt").write_text("same-bytes")
        (self.drive / "unique.txt").write_text("other")
        out = invoke("scan", {"drives": [str(self.drive)]}, env=self.env)
        self.assertTrue(out["ok"])
        self.assertEqual(out["result"]["groups"], 1)
        paths = out["result"]["duplicates"][0]["paths"]
        self.assertEqual(len(paths), 2)

    def test_archive_member_matches_loose_file(self):
        payload = b"nested-twin"
        (self.drive / "loose.bin").write_bytes(payload)
        zpath = self.drive / "pack.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("inner/loose.bin", payload)
            zf.writestr("../escape.txt", b"nope")
        out = invoke("scan", {"drives": [str(self.drive)], "archives": True}, env=self.env)
        self.assertTrue(out["ok"])
        joined = " ".join(p for g in out["result"]["duplicates"] for p in g["paths"])
        self.assertIn("loose.bin", joined)
        self.assertIn("pack.zip!inner/loose.bin", joined)
        self.assertNotIn("escape.txt", joined)

    def test_forbid_keys_drive(self):
        keys = self.home / ".kraken" / "keys"
        keys.mkdir(parents=True)
        b = invoke("scan", {"drives": [str(keys)]}, env=self.env)
        self.assertFalse(b["ok"])

    def test_finish(self):
        self.assertTrue(invoke("finish", {"raw": {"arm": "twin"}}, env=self.env)["result"]["finished"])


if __name__ == "__main__":
    unittest.main()
