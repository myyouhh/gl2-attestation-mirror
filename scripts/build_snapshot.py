#!/usr/bin/env python3

import argparse
import base64
import hashlib
import json
import subprocess
import time
from pathlib import Path

SOURCE = "https://android.googleapis.com/attestation/status"
PREFIX = "GL2-ANDROID-ATTESTATION-MIRROR-V1"


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--valid-seconds", type=int, default=172800)
    args = parser.parse_args()

    if args.valid_seconds < 3600 or args.valid_seconds > 172800:
        raise SystemExit("valid-seconds must be between 3600 and 172800")

    payload = Path(args.input).read_bytes()
    if len(payload) > 2 * 1024 * 1024:
        raise SystemExit("Google attestation status payload is too large")
    parsed = json.loads(payload)
    if not isinstance(parsed, dict) or not isinstance(parsed.get("entries"), dict):
        raise SystemExit("Google attestation status payload is invalid")

    issued_at = int(time.time())
    expires_at = issued_at + args.valid_seconds
    digest = hashlib.sha256(payload).hexdigest()
    message = f"{PREFIX}\n{issued_at}\n{expires_at}\n{digest}".encode("ascii")

    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", args.private_key],
        input=message,
        check=True,
        capture_output=True,
    ).stdout

    snapshot = {
        "schema": 1,
        "source": SOURCE,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "payload_base64": base64url(payload),
        "signature_base64": base64url(signature),
    }
    Path(args.output).write_text(
        json.dumps(snapshot, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
