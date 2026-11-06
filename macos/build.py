#!/usr/bin/env python3
"""Build a native or universal macOS app using Rust and Xcode Command Line Tools."""
import argparse
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {"arm64": "aarch64-apple-darwin", "x86_64": "x86_64-apple-darwin"}


def run(*args, **kwargs):
    subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=[*TARGETS, "universal"], default="universal")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "macos")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("Сборка .app выполняется на macOS с Xcode Command Line Tools")
    run("xcrun", "--find", "clang")
    arches = list(TARGETS) if args.arch == "universal" else [args.arch]
    env = dict(os.environ, MACOSX_DEPLOYMENT_TARGET="11.0")
    for arch in arches:
        run("rustup", "target", "add", TARGETS[arch])
        run("cargo", "build", "--release", "--locked", "--target", TARGETS[arch], env=env)
    version = os.environ.get("AG_FULL_VERSION") or re.search(
        r'^version\s*=\s*"([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M
    ).group(1)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    # Own one fixed subdirectory and refuse to replace arbitrary paths.
    app = output / "Antigravity Unlocker.app"
    if app.is_symlink():
        raise RuntimeError(f"Refusing to replace symlink: {app}")
    if app.exists():
        shutil.rmtree(app)
    contents = app / "Contents"
    binary = contents / "MacOS" / "ag_unlocker"
    binary.parent.mkdir(parents=True)
    (contents / "Resources").mkdir()
    builds = [ROOT / "target" / TARGETS[a] / "release" / "ag_unlocker" for a in arches]
    if len(builds) == 2:
        run("lipo", "-create", *map(str, builds), "-output", str(binary))
    else:
        shutil.copy2(builds[0], binary)
    binary.chmod(0o755)
    with (contents / "Info.plist").open("wb") as f:
        plistlib.dump({
            "CFBundleName": "Antigravity Unlocker",
            "CFBundleDisplayName": "Antigravity Unlocker",
            "CFBundleIdentifier": "com.agunlocker.app",
            "CFBundleExecutable": "ag_unlocker",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": version.replace("_", "."),
            "CFBundleVersion": version.replace("_", "."),
            "LSMinimumSystemVersion": "11.0",
            "NSHighResolutionCapable": True,
        }, f)
    run("plutil", "-lint", str(contents / "Info.plist"))
    run("codesign", "--force", "--sign", "-", str(app))
    run("codesign", "--verify", "--deep", "--strict", str(app))
    run(str(binary), "--version")
    archive = output / f"AG_{version}_macos_{args.arch}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(app, arcname=app.name)
        tar.add(ROOT / "macos" / "README.md", arcname="README.md")
        tar.add(ROOT / "LICENSE", arcname="LICENSE")
    print(f"Готово: {app}\nАрхив: {archive}")


if __name__ == "__main__":
    main()
