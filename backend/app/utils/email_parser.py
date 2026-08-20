"""
Email parsing utilities. Handles raw email strings and .eml files.
Treats all email content as untrusted input.
"""

import email
import email.policy
import re
from email import message_from_string, message_from_bytes
from email.header import decode_header
from typing import Dict, List, Optional, Tuple
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)


def decode_mime_header(value: str) -> str:
    """Decode MIME-encoded email headers safely."""
    if not value:
        return ""
    try:
        parts = decode_header(value)
        decoded = []
        for part, encoding in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(encoding or "utf-8", errors="replace"))
            else:
                decoded.append(str(part))
        return " ".join(decoded)
    except Exception:
        return str(value)


def extract_email_address(header_value: str) -> Tuple[str, str]:
    """
    Extract display name and email address from a header value.
    e.g. '"PayPal Security" <security@paypa1.com>' -> ('PayPal Security', 'security@paypa1.com')
    """
    if not header_value:
        return "", ""

    # Pattern: "Display Name" <email@domain.com>
    match = re.match(r'^"?([^"<]*?)"?\s*<([^>]+)>$', header_value.strip())
    if match:
        display_name = match.group(1).strip()
        email_addr = match.group(2).strip().lower()
        return display_name, email_addr

    # Plain email address
    if "@" in header_value and "<" not in header_value:
        return "", header_value.strip().lower()

    return "", header_value.strip()


def extract_domain_from_email(email_addr: str) -> str:
    """Extract domain from an email address."""
    if "@" in email_addr:
        return email_addr.split("@")[-1].lower().strip()
    return ""


def html_to_text(html_content: str) -> str:
    """Convert HTML email body to plain text safely."""
    try:
        soup = BeautifulSoup(html_content, "lxml")
        # Remove script and style elements
        for tag in soup(["script", "style", "head"]):
            tag.decompose()
        return soup.get_text(separator=" ", strip=True)
    except Exception:
        # Fallback: strip all HTML tags with regex
        return re.sub(r'<[^>]+>', ' ', html_content)


def extract_urls_from_text(text: str) -> List[str]:
    """Extract all URLs from plain text."""
    url_pattern = re.compile(
        r'https?://[^\s\'"<>]+|'
        r'www\.[^\s\'"<>]+',
        re.IGNORECASE
    )
    urls = url_pattern.findall(text)
    # Clean trailing punctuation
    cleaned = []
    for url in urls:
        url = url.rstrip('.,;:!?)]}"\'>\\')
        if url:
            cleaned.append(url)
    return list(set(cleaned))


def extract_urls_from_html(html_content: str) -> List[str]:
    """Extract URLs from HTML including href attributes."""
    urls = []
    try:
        soup = BeautifulSoup(html_content, "lxml")
        for tag in soup.find_all(href=True):
            href = tag.get('href', '')
            if href and (href.startswith('http') or href.startswith('www')):
                urls.append(href)
        for tag in soup.find_all(src=True):
            src = tag.get('src', '')
            if src and (src.startswith('http') or src.startswith('www')):
                urls.append(src)
    except Exception:
        pass
    # Also extract from raw text
    urls.extend(extract_urls_from_text(html_content))
    return list(set(urls))


def parse_email_string(raw_email: str) -> Dict:
    """
    Parse a raw email string into structured components.
    Returns a normalized dict regardless of input format.
    """
    result = {
        "from_address": "",
        "from_display_name": "",
        "from_email": "",
        "to": "",
        "reply_to": "",
        "reply_to_email": "",
        "return_path": "",
        "subject": "",
        "body_text": "",
        "body_html": "",
        "headers": {},
        "received_headers": [],
        "authentication_results": "",
        "spf": "",
        "dkim": "",
        "dmarc": "",
        "all_urls": [],
        "parse_error": None,
    }

    try:
        msg = message_from_string(raw_email, policy=email.policy.default)
    except Exception as e:
        # If proper parsing fails, do manual extraction
        logger.warning(f"Email parse failed, using manual extraction: {e}")
        result["parse_error"] = str(e)
        result.update(_manual_parse(raw_email))
        return result

    # Headers
    raw_from = decode_mime_header(msg.get("From", ""))
    result["from_address"] = raw_from
    display_name, from_email = extract_email_address(raw_from)
    result["from_display_name"] = display_name
    result["from_email"] = from_email.lower()

    result["to"] = decode_mime_header(msg.get("To", ""))
    raw_reply_to = decode_mime_header(msg.get("Reply-To", ""))
    result["reply_to"] = raw_reply_to
    _, reply_to_email = extract_email_address(raw_reply_to)
    result["reply_to_email"] = reply_to_email.lower()

    result["return_path"] = decode_mime_header(msg.get("Return-Path", ""))
    result["subject"] = decode_mime_header(msg.get("Subject", ""))

    # Authentication headers
    result["authentication_results"] = msg.get("Authentication-Results", "")
    received_spf = msg.get("Received-SPF", "")
    result["spf"] = received_spf
    result["dkim"] = msg.get("DKIM-Signature", "")[:100] if msg.get("DKIM-Signature") else ""
    result["dmarc"] = ""  # Usually in Authentication-Results

    # Parse Authentication-Results for SPF/DKIM/DMARC
    auth_results = result["authentication_results"].lower()
    if "spf=pass" in auth_results:
        result["spf"] = "pass"
    elif "spf=fail" in auth_results:
        result["spf"] = "fail"
    elif "spf=softfail" in auth_results:
        result["spf"] = "softfail"

    if "dkim=pass" in auth_results:
        result["dkim"] = "pass"
    elif "dkim=fail" in auth_results:
        result["dkim"] = "fail"

    if "dmarc=pass" in auth_results:
        result["dmarc"] = "pass"
    elif "dmarc=fail" in auth_results:
        result["dmarc"] = "fail"

    # Received headers
    result["received_headers"] = msg.get_all("Received", [])

    # Collect all headers as dict
    for key in msg.keys():
        result["headers"][key] = decode_mime_header(msg.get(key, ""))

    # Body extraction
    body_text = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")

                if content_type == "text/plain":
                    body_text += text
                elif content_type == "text/html":
                    body_html += text
            except Exception:
                continue
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
                if content_type == "text/html":
                    body_html = text
                    body_text = html_to_text(text)
                else:
                    body_text = text
        except Exception:
            body_text = str(msg.get_payload())

    result["body_text"] = body_text
    result["body_html"] = body_html

    # URL extraction
    all_urls = extract_urls_from_text(body_text)
    if body_html:
        all_urls.extend(extract_urls_from_html(body_html))
    result["all_urls"] = list(set(all_urls))

    return result


def _manual_parse(raw_email: str) -> Dict:
    """Fallback manual parser for non-standard email formats."""
    result = {
        "from_address": "",
        "from_display_name": "",
        "from_email": "",
        "to": "",
        "reply_to": "",
        "reply_to_email": "",
        "return_path": "",
        "subject": "",
        "body_text": "",
        "body_html": "",
        "headers": {},
        "received_headers": [],
        "authentication_results": "",
        "spf": "",
        "dkim": "",
        "dmarc": "",
        "all_urls": [],
    }

    lines = raw_email.splitlines()
    in_body = False
    body_lines = []

    for line in lines:
        if in_body:
            body_lines.append(line)
            continue

        if line.strip() == "":
            in_body = True
            continue

        lower = line.lower()
        if lower.startswith("from:"):
            value = line[5:].strip()
            result["from_address"] = value
            dn, ea = extract_email_address(value)
            result["from_display_name"] = dn
            result["from_email"] = ea
        elif lower.startswith("to:"):
            result["to"] = line[3:].strip()
        elif lower.startswith("reply-to:"):
            value = line[9:].strip()
            result["reply_to"] = value
            _, ea = extract_email_address(value)
            result["reply_to_email"] = ea
        elif lower.startswith("subject:"):
            result["subject"] = line[8:].strip()

    result["body_text"] = "\n".join(body_lines)
    result["all_urls"] = extract_urls_from_text(result["body_text"])

    return result


def parse_structured_email(email_data: Dict) -> Dict:
    """
    Parse email from structured dict (from API request).
    Handles the case where user manually enters fields.
    """
    from_address = email_data.get("from_address", "") or email_data.get("from", "")
    body = email_data.get("body", "")
    headers = email_data.get("headers", {})

    display_name, from_email = extract_email_address(from_address)
    _, reply_to_email = extract_email_address(email_data.get("reply_to", ""))

    all_urls = extract_urls_from_text(body)

    # Check if body contains HTML
    if "<html" in body.lower() or "<a href" in body.lower():
        all_urls.extend(extract_urls_from_html(body))
        body_text = html_to_text(body)
    else:
        body_text = body

    return {
        "from_address": from_address,
        "from_display_name": display_name,
        "from_email": from_email.lower(),
        "to": email_data.get("to", ""),
        "reply_to": email_data.get("reply_to", ""),
        "reply_to_email": reply_to_email.lower(),
        "return_path": headers.get("Return-Path", ""),
        "subject": email_data.get("subject", ""),
        "body_text": body_text,
        "body_html": body if "<html" in body.lower() else "",
        "headers": headers,
        "received_headers": [],
        "authentication_results": headers.get("Authentication-Results", ""),
        "spf": headers.get("Received-SPF", ""),
        "dkim": headers.get("DKIM-Signature", ""),
        "dmarc": "",
        "all_urls": list(set(all_urls)),
        "parse_error": None,
    }
