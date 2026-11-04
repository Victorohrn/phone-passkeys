#!/usr/bin/env python3
"""Packages the extension directory into an .xpi (a zip with manifest.json at the root)."""
import pathlib
import sys
import zipfile

if len(sys.argv) != 3:
    sys.exit("usage: build-xpi.py <extension-dir> <output.xpi>")

src = pathlib.Path(sys.argv[1]).resolve()
out = pathlib.Path(sys.argv[2]).resolve()
if not (src / "manifest.json").is_file():
    sys.exit(f"{src} does not contain manifest.json")
out.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
    for path in sorted(src.rglob("*")):
        if path.is_file():
            zf.write(path, path.relative_to(src).as_posix())
print(out)
