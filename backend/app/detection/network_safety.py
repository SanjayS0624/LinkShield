"""Hostnames that must never trigger external enrichment lookups."""

SPECIAL_USE_SUFFIXES = (
    "localhost", "local", "internal", "lan", "home.arpa", "test", "invalid", "example", "onion",
)


def is_special_use_hostname(host: str) -> bool:
    normalized = host.rstrip(".").casefold()
    return any(normalized == suffix or normalized.endswith("." + suffix)
               for suffix in SPECIAL_USE_SUFFIXES)
