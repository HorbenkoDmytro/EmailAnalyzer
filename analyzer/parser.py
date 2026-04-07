"""
Email parser module.

Parses .eml files into a structured EmailData dataclass, extracting
headers, body parts, and attachment metadata using Python's built-in
email library — no extra dependencies required.
"""

import email
import email.policy
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path
from typing import Optional


@dataclass
class Attachment:
    filename: str
    content_type: str
    size_bytes: int


@dataclass
class EmailData:
    # Core headers
    from_address: str
    from_display_name: str
    to_addresses: list[str]
    reply_to: Optional[str]
    subject: str
    date: Optional[str]
    message_id: Optional[str]

    # Authentication headers (raw strings from the email)
    authentication_results: Optional[str]
    dkim_signature: Optional[str]
    received_spf: Optional[str]
    x_originating_ip: Optional[str]
    x_mailer: Optional[str]

    # Routing
    received_chain: list[str]

    # Body content
    body_plain: str
    body_html: str

    # Attachments
    attachments: list[Attachment]

    # Raw headers dict for flexibility
    raw_headers: dict[str, list[str]]


def parse_email_file(filepath: str | Path) -> EmailData:
    """Parse an .eml file and return a structured EmailData object.

    Args:
        filepath: Path to the .eml file.

    Returns:
        EmailData with all relevant fields populated.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file cannot be parsed as an email.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Email file not found: {filepath}")

    raw_bytes = path.read_bytes()
    try:
        msg: Message = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
    except Exception as exc:
        raise ValueError(f"Failed to parse email file: {exc}") from exc

    return _extract_data(msg)


def parse_email_string(raw_email: str) -> EmailData:
    """Parse a raw email string (useful for testing).

    Args:
        raw_email: Raw email content as a string.

    Returns:
        EmailData with all relevant fields populated.
    """
    msg: Message = email.message_from_string(raw_email, policy=email.policy.compat32)
    return _extract_data(msg)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_data(msg: Message) -> EmailData:
    from_raw = msg.get("From", "")
    from_display, from_address = _split_address(from_raw)

    reply_to_raw = msg.get("Reply-To")
    reply_to = _split_address(reply_to_raw)[1] if reply_to_raw else None

    to_raw = msg.get("To", "")
    to_addresses = [_split_address(a.strip())[1] for a in to_raw.split(",") if a.strip()]

    received_chain = msg.get_all("Received") or []

    body_plain, body_html, attachments = _extract_body_parts(msg)

    raw_headers: dict[str, list[str]] = {}
    for key in set(msg.keys()):
        raw_headers[key.lower()] = msg.get_all(key) or []

    return EmailData(
        from_address=from_address,
        from_display_name=from_display,
        to_addresses=to_addresses,
        reply_to=reply_to,
        subject=msg.get("Subject", ""),
        date=msg.get("Date"),
        message_id=msg.get("Message-ID"),
        authentication_results=msg.get("Authentication-Results"),
        dkim_signature=msg.get("DKIM-Signature"),
        received_spf=msg.get("Received-SPF"),
        x_originating_ip=msg.get("X-Originating-IP"),
        x_mailer=msg.get("X-Mailer"),
        received_chain=received_chain,
        body_plain=body_plain,
        body_html=body_html,
        attachments=attachments,
        raw_headers=raw_headers,
    )


def _split_address(raw: str) -> tuple[str, str]:
    """Split 'Display Name <email@domain.com>' into (display_name, email).

    Returns ('', raw) if the format is just a plain email address.
    """
    raw = raw.strip()
    if "<" in raw and ">" in raw:
        display = raw[: raw.index("<")].strip().strip('"')
        addr = raw[raw.index("<") + 1 : raw.index(">")].strip()
        return display, addr
    return "", raw


def _extract_body_parts(msg: Message) -> tuple[str, str, list[Attachment]]:
    """Walk MIME parts and extract plain text, HTML, and attachment info."""
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = part.get("Content-Disposition", "")

            if "attachment" in disposition:
                filename = part.get_filename() or "unknown"
                payload = part.get_payload(decode=True) or b""
                attachments.append(
                    Attachment(
                        filename=filename,
                        content_type=content_type,
                        size_bytes=len(payload),
                    )
                )
            elif content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    plain_parts.append(payload.decode("utf-8", errors="replace"))
            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    html_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            decoded = payload.decode("utf-8", errors="replace")
            if content_type == "text/html":
                html_parts.append(decoded)
            else:
                plain_parts.append(decoded)

    return "\n".join(plain_parts), "\n".join(html_parts), attachments
