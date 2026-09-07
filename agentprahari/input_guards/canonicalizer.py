"""
AgentPrahari Text Canonicalization and De-obfuscation Engine.
Normalizes encoded, homoglyphic, zero-width, and escaped strings into canonical representations
without destructively altering the original text, preventing pattern bypass by multi-layer encoding.
"""

from __future__ import annotations
from dataclasses import dataclass, field
import html
import re
import unicodedata
import urllib.parse
from typing import List, Tuple

ZERO_WIDTH_REGEX = re.compile(r"[\u200B-\u200D\uFEFF\u202A-\u202E\u00AD]")

# Common leet-speak and Cyrillic homoglyph substitutions to ASCII letters
HOMOGLYPH_MAP = str.maketrans({
    "1": "i",
    "!": "i",
    "|": "i",
    "0": "o",
    "3": "e",
    "4": "a",
    "@": "a",
    "5": "s",
    "$": "s",
    "7": "t",
    "+": "t",
    "8": "b",
    # Cyrillic homoglyphs
    "\u0430": "a",  # Cyrillic a
    "\u0435": "e",  # Cyrillic e
    "\u043e": "o",  # Cyrillic o
    "\u0440": "p",  # Cyrillic r
    "\u0441": "c",  # Cyrillic s
    "\u0443": "y",  # Cyrillic u
    "\u0445": "x",  # Cyrillic h
    "\u0456": "i",  # Cyrillic i
    "\u0410": "A",
    "\u0412": "B",
    "\u0415": "E",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0422": "T",
    "\u0425": "X",
})


@dataclass
class CanonicalizedText:
    """
    Rich representation of canonicalized text that preserves the original input
    while exposing normalized and alternate representations for security checks.
    """
    original: str
    normalized: str
    representations: List[str] = field(default_factory=list)
    transformations: List[str] = field(default_factory=list)

    @property
    def is_transformed(self) -> bool:
        return bool(self.transformations) or self.normalized != self.original

    def __iter__(self):
        """Allows unpacking as (normalized, transformations) for backward compatibility."""
        return iter((self.normalized, self.transformations))


def strip_zero_width(text: str) -> str:
    """Removes all zero-width, non-printable, and directional formatting characters."""
    return ZERO_WIDTH_REGEX.sub("", text)


def decode_unicode_escapes(text: str) -> str:
    """Decodes unicode escape sequences like \\u0069 or \\U00000069 safely with bounds."""
    def _replace_4(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    def _replace_8(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    res = re.sub(r"\\u([0-9a-fA-F]{4})", _replace_4, text)
    res = re.sub(r"\\U([0-9a-fA-F]{8})", _replace_8, res)
    return res


def decode_url_percent(text: str, max_iterations: int = 3) -> Tuple[str, int]:
    """Recursively decodes percent-encoded characters with bounded recursion to avoid DoS."""
    current = text
    iterations = 0
    for i in range(max_iterations):
        try:
            decoded = urllib.parse.unquote(current)
            if decoded == current:
                break
            current = decoded
            iterations += 1
        except Exception:
            break
    return current, iterations


def decode_html_entities(text: str) -> str:
    """Decodes HTML decimal/hex entities (e.g. &#105; -> i, &lt; -> <)."""
    return html.unescape(text)


def canonicalize(text: str, max_len: int = 200_000) -> CanonicalizedText:
    """
    Produces a CanonicalizedText containing:
    - original: unmodified input text (for DiffTracker, audit trails, and offsets)
    - normalized: fully de-obfuscated representation (NFKC + unquoted + unescaped)
    - representations: list of intermediate representations (original, normalized, homoglyph-mapped)
    - transformations: tags of applied transformations
    """
    # Guard against pathological input length for bounded processing
    if len(text) > max_len:
        text = text[:max_len]

    applied: List[str] = []
    current = text

    # 1. Unicode NFKC normalization (turns fullwidth chars into standard ASCII)
    norm = unicodedata.normalize("NFKC", current)
    if norm != current:
        applied.append("nfkc_normalization")
        current = norm

    # 2. Strip zero-width characters and byte order marks (BOM)
    stripped = strip_zero_width(current)
    if stripped != current:
        applied.append("zero_width_stripped")
        current = stripped

    # 3. Unicode escape decoding (\\u0069...)
    if "\\u" in current or "\\U" in current:
        u_decoded = decode_unicode_escapes(current)
        if u_decoded != current:
            applied.append("unicode_escapes_decoded")
            current = u_decoded

    # 4. Bounded URL percent decoding (handles double/multi-layer %253c...)
    if "%" in current:
        url_decoded, iters = decode_url_percent(current, max_iterations=3)
        if iters > 0:
            applied.append(f"url_percent_decoded_x{iters}")
            current = url_decoded

    # 5. HTML entity unescaping
    if "&#" in current or "&amp;" in current or "&lt;" in current or "&gt;" in current:
        html_decoded = decode_html_entities(current)
        if html_decoded != current:
            applied.append("html_entities_decoded")
            current = html_decoded

    # Build representation set
    reps = [text]
    if current != text:
        reps.append(current)

    # 6. Homoglyph / leetspeak representation
    homoglyph_rep = current.translate(HOMOGLYPH_MAP)
    if homoglyph_rep != current and homoglyph_rep not in reps:
        reps.append(homoglyph_rep)

    return CanonicalizedText(
        original=text,
        normalized=current,
        representations=reps,
        transformations=applied,
    )


def canonicalize_text(text: str) -> CanonicalizedText:
    """Canonicalizes text and returns CanonicalizedText, supporting tuple unpacking (norm, trans)."""
    return canonicalize(text)


def get_homoglyph_normalized(text: str) -> str:
    """Translates common leet-speak / homoglyph characters."""
    return text.translate(HOMOGLYPH_MAP)
