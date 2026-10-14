#!/usr/bin/env python3

import argparse
import hashlib
import json
from email import policy
from email.parser import BytesParser
from pathlib import Path


def calculate_sha256(file_path: Path) -> str:
    """Calculate the SHA-256 hash of the original email file."""
    digest = hashlib.sha256()

    with file_path.open("rb") as email_file:
        for chunk in iter(lambda: email_file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def analyze_email(file_path: Path) -> dict:
    """Extract selected email headers without executing attachments."""
    if not file_path.is_file():
        raise FileNotFoundError(f"Email file not found: {file_path}")

    raw_email = file_path.read_bytes()

    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    header_names = [
        "From",
        "To",
        "Reply-To",
        "Return-Path",
        "Subject",
        "Date",
        "Message-ID",
        "Authentication-Results",
        "Received-SPF",
    ]

    headers = {}

    for name in header_names:
        values = message.get_all(name, [])

        if values:
            headers[name] = [str(value) for value in values]

    received_headers = message.get_all("Received", [])

    dkim_signatures = message.get_all("DKIM-Signature", [])

    attachments = []

    for part in message.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()

        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""

            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })

    return {
        "file": file_path.name,
        "file_sha256": calculate_sha256(file_path),
        "headers": headers,
        "received_header_count": len(received_headers),
        "received_headers": [str(value) for value in received_headers],
        "dkim_signature_count": len(dkim_signatures),
        "attachments": attachments,
        "analysis_limitations": [
            "Header extraction does not validate SPF, DKIM, or DMARC.",
            "Header values can be forged.",
            "Attachment hashes identify files but do not determine whether they are malicious.",
            "No URLs are visited and no attachments are executed.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract headers and attachment hashes from an EML file."
    )

    parser.add_argument("eml_file", type=Path, help="Path to the .eml file")
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for the JSON report",
    )

    args = parser.parse_args()

    try:
        result = analyze_email(args.eml_file)

        report = json.dumps(result, indent=2, ensure_ascii=False)

        if args.output:
            args.output.write_text(report + "\n", encoding="utf-8")
            print(f"Report written to: {args.output}")
        else:
            print(report)

    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()