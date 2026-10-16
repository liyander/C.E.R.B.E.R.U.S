"""Remove common identifiers and credentials from outbound cloud model prompts."""
import ipaddress
import re
from urllib.parse import urlparse

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
SECRET = re.compile(r"(?i)\b((?:api[_-]?key|password|secret|token|authorization)\s*[:=]\s*)([^\s,;]+)")
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+")
AUTH_HEADER = re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/-]+")
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.%]*")


def is_cloud(base_url: str) -> bool:
    host = (urlparse(base_url).hostname or "").lower()
    if host in {"localhost", "::1"} or host.endswith((".local", ".lan")):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True


def redact(value: str) -> str:
    value = AUTH_HEADER.sub("Authorization: [REDACTED]", value)
    value = BEARER.sub("Bearer [REDACTED]", value)
    value = SECRET.sub(lambda m: m.group(1) + "[REDACTED]", value)
    value = EMAIL.sub("[EMAIL]", value)
    def replace_v6(match):
        try:
            ipaddress.IPv6Address(match.group())
        except ipaddress.AddressValueError:
            return match.group()
        return "[IP]"
    value = IPV6.sub(replace_v6, value)
    def replace_ip(match):
        try:
            ipaddress.IPv4Address(match.group())
        except ipaddress.AddressValueError:
            return match.group()
        return "[IP]"
    return IPV4.sub(replace_ip, value)


def messages(items: list[dict]) -> list[dict]:
    cleaned = []
    for item in items:
        row = dict(item)
        if isinstance(row.get("content"), str):
            row["content"] = redact(row["content"])
        if isinstance(row.get("tool_calls"), list):
            row["tool_calls"] = [{**call, "function": {**call.get("function", {}),
                "arguments": redact(call.get("function", {}).get("arguments", ""))}}
                for call in row["tool_calls"]]
        cleaned.append(row)
    return cleaned
