#!/usr/bin/env python3
"""twin — exact file duplicates on declared drives. No unpack to disk."""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import stat
import sys
import tarfile
import zipfile
from collections import defaultdict
from pathlib import Path

VERSION = "0.1.0"
PROTOCOL = 1
DENIED = ("/keys", "keys/", "licenses.json", "kraken_catalog", "topta.co", "catalog.json")
CHUNK = 1024 * 1024
ARCHIVE_EXT = {".zip", ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tbz2"}


def ok(ident, result):
    return {"v": PROTOCOL, "id": ident, "ok": True, "result": result}


def err(ident, code, message):
    return {"v": PROTOCOL, "id": ident, "ok": False, "error": {"code": code, "message": message}}


def data_dir(payload: dict) -> Path:
    if payload.get("dir"):
        p = Path(str(payload["dir"]))
    else:
        h = os.environ.get("KRAKEN_HOME") or str(Path.home())
        p = Path(h) / ".kraken" / "data" / "twin"
    text = str(p).replace("\\", "/").lower()
    if any(d in text for d in DENIED):
        raise PermissionError("forbidden path")
    p.mkdir(parents=True, exist_ok=True)
    return p


def report_path(payload: dict) -> Path:
    return data_dir(payload) / "report.json"


def forbidden(path: Path) -> bool:
    text = str(path).replace("\\", "/").lower()
    return any(d in text for d in DENIED)


def under_drive(path: Path, drives: list[Path]) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    for drive in drives:
        try:
            resolved.relative_to(drive.resolve())
            return True
        except ValueError:
            continue
    return False


def sha256_file(path: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            while True:
                buf = fh.read(CHUNK)
                if not buf:
                    break
                h.update(buf)
    except OSError:
        return None
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_archive(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(ext) for ext in ARCHIVE_EXT)


def safe_member(name: str) -> bool:
    n = name.replace("\\", "/")
    if n.startswith("/") or n.startswith("\\"):
        return False
    parts = Path(n).parts
    return ".." not in parts


def iter_zip_members(path: Path):
    try:
        zf = zipfile.ZipFile(path, "r")
    except (zipfile.BadZipFile, OSError):
        return
    with zf:
        for info in zf.infolist():
            if info.is_dir() or not safe_member(info.filename):
                continue
            if info.flag_bits & 0x1:
                continue
            try:
                data = zf.read(info)
            except RuntimeError:
                continue
            yield f"{path}!{info.filename}", info.file_size, sha256_bytes(data)


def iter_tar_members(path: Path):
    try:
        tf = tarfile.open(path, "r:*")
    except (tarfile.TarError, OSError):
        return
    with tf:
        for member in tf.getmembers():
            if not member.isfile() or not safe_member(member.name):
                continue
            if member.size < 0 or member.size > 512 * 1024 * 1024:
                continue
            fh = tf.extractfile(member)
            if fh is None:
                continue
            h = hashlib.sha256()
            while True:
                buf = fh.read(CHUNK)
                if not buf:
                    break
                h.update(buf)
            yield f"{path}!{member.name}", member.size, h.hexdigest()


def walk_drive(drive: Path, max_bytes: int | None):
    if not drive.exists() or forbidden(drive):
        return
    for root, dirs, files in os.walk(drive, followlinks=False):
        root_p = Path(root)
        if forbidden(root_p):
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not forbidden(root_p / d)]
        for name in files:
            p = root_p / name
            if forbidden(p) or p.is_symlink():
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if max_bytes is not None and st.st_size > max_bytes:
                continue
            yield p, st.st_size


def scan(drives: list[str], max_bytes: int | None, archives: bool) -> dict:
    roots = []
    for raw in drives:
        p = Path(raw).expanduser()
        if forbidden(p):
            raise PermissionError(f"forbidden drive {p}")
        if not p.exists() or not p.is_dir():
            continue
        roots.append(p.resolve())
    if not roots:
        raise ValueError("no usable drives")

    by_size: dict[int, list[Path]] = defaultdict(list)
    files = 0
    archives_found: list[Path] = []
    for drive in roots:
        for path, size in walk_drive(drive, max_bytes):
            files += 1
            by_size[size].append(path)
            if archives and is_archive(path):
                archives_found.append(path)

    digest_map: dict[str, list[str]] = defaultdict(list)
    hashed = 0
    member_sizes: set[int] = set()
    if archives:
        for path in archives_found:
            opener = iter_zip_members if path.name.lower().endswith(".zip") else iter_tar_members
            for loc, sz, member_digest in opener(path):
                member_sizes.add(sz)
                digest_map[member_digest].append(loc)
                hashed += 1

    for size, paths in by_size.items():
        if size == 0:
            continue
        interesting = len(paths) > 1 or size in member_sizes
        if not interesting:
            continue
        for path in paths:
            if archives and is_archive(path):
                continue
            digest = sha256_file(path)
            if digest:
                digest_map[digest].append(str(path))
                hashed += 1

    groups = [
        {"sha256": digest, "count": len(locs), "paths": sorted(locs)}
        for digest, locs in digest_map.items()
        if len(locs) > 1
    ]
    groups.sort(key=lambda g: (-g["count"], g["sha256"]))
    return {
        "arm": "twin",
        "drives": [str(r) for r in roots],
        "files": files,
        "hashed": hashed,
        "groups": len(groups),
        "duplicates": groups,
        "archives": archives,
    }


def dispatch(req: dict) -> dict:
    action = req.get("action") or "ping"
    ident = req.get("id")
    p = req.get("payload") or {}
    if action in ("", "ping"):
        return ok(ident, {
            "arm": "twin", "version": VERSION, "protocol": PROTOCOL,
            "platform": f"{sys.platform}-{platform.machine()}",
            "brand": "TopTaco", "tagline": "One binary. Many tentacles.",
        })
    if action == "finish":
        raw = dict(p.get("raw") or {"arm": "twin"})
        raw.update(p.get("patch") or {})
        raw["finished"] = True
        return ok(ident, raw)
    try:
        store = data_dir(p)
    except PermissionError as exc:
        return err(ident, "forbidden", str(exc))
    if action == "clear":
        rp = report_path(p)
        if rp.exists():
            rp.unlink()
        return ok(ident, {"cleared": True, "arm": "twin"})
    if action == "report":
        rp = report_path(p)
        if not rp.exists():
            return ok(ident, {"arm": "twin", "groups": 0, "duplicates": []})
        return ok(ident, json.loads(rp.read_text(encoding="utf-8")))
    if action == "scan":
        drives = list(p.get("drives") or [])
        if not drives:
            return err(ident, "missing", "payload.drives required")
        try:
            result = scan(drives, p.get("max_bytes"), bool(p.get("archives", True)))
        except PermissionError as exc:
            return err(ident, "forbidden", str(exc))
        except ValueError as exc:
            return err(ident, "bad_drives", str(exc))
        rp = report_path(p)
        rp.write_text(json.dumps(result, indent=2), encoding="utf-8")
        os.chmod(rp, 0o600)
        return ok(ident, result)
    return err(ident, "unknown_action", f"unknown action {action}")


def main() -> int:
    raw = sys.stdin.read()
    req = json.loads(raw) if raw.strip() else {"action": "ping"}
    json.dump(dispatch(req), sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
