# -*- coding: utf-8 -*-
"""
Created on Sat Oct 24 18:42:15 2026

""Verify local downloaded files against a trusted SHA-256 manifest.

Usage: python file_integrity_checker.py
       python file_integrity_checker.py --directory /path/to/downloads
       python file_integrity_checker.py --manifest expected_hashes.json
"""
import argparse
import hashlib
import json
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def calculate_text_hashes():
    """Calculate MD5, SHA-1, and SHA-256 hashes for text."""

    print("\nEnter your text below.")
    print("Type END on a new line when finished.")

    lines = []

    while True:
        line = input()

        if line == "END":
            break

        lines.append(line)

    text = "\n".join(lines)
    text_bytes = text.encode("utf-8")

    md5_hash = hashlib.md5(text_bytes).hexdigest()
    sha1_hash = hashlib.sha1(text_bytes).hexdigest()
    sha256_hash = hashlib.sha256(text_bytes).hexdigest()

    print("\n--- Hash Results ---")
    print("MD5:     ", md5_hash)
    print("SHA-1:   ", sha1_hash)
    print("SHA-256: ", sha256_hash)
def main() -> int:
    print("\n=== Cybersecurity Hash Calculator ===")
    print("1. Calculate text hashes")
    print("2. Check file integrity")

    choice = input("Choose an option (1 or 2): ")

    if choice == "1":
        calculate_text_hashes()
        return 0

    elif choice == "2":
        print("\nStarting file integrity checker...\n")

    else:
        print("Invalid choice. Please run the program again and select 1 or 2.")
        return 2

    parser = argparse.ArgumentParser(description="Check SHA-256 download integrity")
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parent,
                        help="Folder containing downloaded files (default: script folder)")
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parent / "expected_hashes.json",
                        help="Trusted JSON file of expected SHA-256 hashes")
    args = parser.parse_args()

    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        if manifest.get("algorithm") != "SHA-256" or not isinstance(manifest.get("files"), dict):
            raise ValueError("Manifest must contain algorithm SHA-256 and a files object")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR reading manifest: {error}")
        return 2

    failed = 0
    for filename, expected in manifest["files"].items():
        if (not isinstance(filename, str) or Path(filename).name != filename
                or not isinstance(expected, str) or len(expected) != 64
                or any(c not in "0123456789abcdefABCDEF" for c in expected)):
            print(f"ERROR: Invalid manifest entry for {filename!r}")
            return 2
        path = args.directory / filename
        if not path.is_file():
            print(f"MISSING  {filename}")
            failed += 1
            continue
        try:
            actual = sha256_file(path)
        except OSError as error:
            print(f"ERROR    {filename}: {error}")
            failed += 1
            continue
        if actual.lower() == expected.lower():
            print(f"PASS     {filename}  SHA-256: {actual}")
        else:
            print(f"FAIL     {filename}")
            print(f"         Expected: {expected.lower()}")
            print(f"         Actual:   {actual}")
            failed += 1

    print(f"\nResult: {len(manifest['files']) - failed}/{len(manifest['files'])} files verified")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
