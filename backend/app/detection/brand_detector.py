"""Explainable brand lookalike checks. Similarity is not a phishing probability."""

from difflib import SequenceMatcher
import re
from typing import Any


CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ӏ": "l",
    "α": "a", "ο": "o", "ρ": "p", "υ": "u", "χ": "x", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "ε": "e",
})
GENERIC_LABELS = {"account", "auth", "billing", "help", "login", "secure", "security", "service", "support", "verify"}


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold().translate(CONFUSABLES))


def _brand_terms(brand: dict[str, Any]) -> set[str]:
    terms = {brand["name"], *brand.get("aliases", []), *brand.get("keywords", [])}
    return {_compact(term) for term in terms if _compact(term)}


def detect_brands(host: str, brands: list[dict[str, Any]]) -> dict[str, Any]:
    """Report plausible domain similarity and brand-word use, without verdict language."""
    hostname = host.casefold().rstrip(".")
    detected: list[dict[str, Any]] = []
    for brand in brands:
        official_domains = [domain.casefold().rstrip(".") for domain in brand.get("official_domains", [])]
        if any(hostname == official or hostname.endswith("." + official) for official in official_domains):
            continue

        terms = _brand_terms(brand)
        labels = hostname.split(".")
        candidates: dict[str, str] = {}
        unicode_or_punycode = False
        for label in labels:
            decoded = label
            if label.startswith("xn--"):
                try:
                    decoded = label.encode("ascii").decode("idna")
                    unicode_or_punycode = True
                except UnicodeError:
                    pass
            if any(ord(char) > 127 for char in decoded):
                unicode_or_punycode = True
            chunks = [part for part in re.split(r"[^a-z0-9]+", label) if part]
            raw_candidates = [*chunks, label, decoded,
                              *(part for part in re.split(r"[^a-z0-9]+", decoded) if part)]
            # Catch concatenations such as "pay-pal-login" after ignoring common action words.
            raw_candidates.append("".join(part for part in chunks if part not in GENERIC_LABELS))
            for raw_candidate in raw_candidates:
                compact_candidate = _compact(raw_candidate)
                if compact_candidate:
                    candidates.setdefault(compact_candidate, raw_candidate)

        comparisons = [(term, candidate, SequenceMatcher(None, term, candidate).ratio())
                       for term in terms for candidate in candidates if candidate]
        exact = [(term, candidate, score) for term, candidate, score in comparisons if term == candidate]
        best = max(exact or comparisons, key=lambda match: match[2], default=None)
        if best is None:
            continue
        term, candidate, similarity = best
        if similarity < 0.74:
            continue

        exact_keyword = term == candidate
        detected.append({
            "brand": brand["name"],
            "matched_label_similarity": round(similarity, 2),
            "official_domains": official_domains,
            "matched_text": candidates[candidate],
            "reason": ("A Unicode or punycode hostname label resembles a configured brand name."
                       if unicode_or_punycode else "A hostname contains a brand-related word or a similar spelling outside the configured official domains."
                       if exact_keyword else "A hostname label is textually similar to a configured brand name."),
        })

    detected.sort(key=lambda item: (-item["matched_label_similarity"], item["brand"].casefold()))
    return {
        "status": "review" if detected else "no_match",
        "matches": detected[:5],
        "note": "Domain similarity is a review signal, not a probability or proof of impersonation.",
    }
