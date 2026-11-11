#!/usr/bin/env python3
"""Inject an SBOM file into a wheel's .dist-info/sboms/ directory (PEP 770).

Usage:
    python scripts/inject_sbom.py <wheel.whl> <sbom.json>
"""
from __future__ import annotations
import base64
import hashlib
import pathlib
import sys
import zipfile


def _dist_info_prefix(zf: zipfile.ZipFile) -> str:
    for name in zf.namelist():
        if ".dist-info/METADATA" in name:
            return name.split(".dist-info/")[0] + ".dist-info"
    raise RuntimeError("No .dist-info directory found in wheel.")


def _sha256_record(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def inject(wheel: pathlib.Path, sbom: pathlib.Path) -> None:
    sbom_data = sbom.read_bytes()

    with zipfile.ZipFile(wheel, "r") as zf:
        dist_info = _dist_info_prefix(zf)
        entries = {info.filename: (info, zf.read(info.filename)) for info in zf.infolist()}

    arc_name = f"{dist_info}/sboms/{sbom.name}"
    sbom_info = zipfile.ZipInfo(arc_name)
    sbom_info.compress_type = zipfile.ZIP_DEFLATED
    entries[arc_name] = (sbom_info, sbom_data)

    # Append SBOM to RECORD (RECORD's own entry keeps empty hash per PEP 427)
    record_arc = f"{dist_info}/RECORD"
    record_info, record_bytes = entries[record_arc]
    lines = [ln for ln in record_bytes.decode().splitlines() if ln.split(",")[0] != arc_name]
    lines.append(f"{arc_name},{_sha256_record(sbom_data)},{len(sbom_data)}")
    entries[record_arc] = (record_info, ("\n".join(lines) + "\n").encode())

    tmp = wheel.with_suffix(".tmp")
    with zipfile.ZipFile(tmp, "w") as out:
        for info, data in entries.values():
            out.writestr(info, data)
    tmp.replace(wheel)
    print(f"Injected {arc_name} into {wheel.name}")


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(f"Usage: {sys.argv[0]} <wheel.whl> <sbom.json>")
    inject(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))


if __name__ == "__main__":
    main()
