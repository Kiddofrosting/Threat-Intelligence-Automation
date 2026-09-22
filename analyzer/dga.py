"""Multi-signal domain-generation-algorithm (DGA) heuristic scoring.

No single signal here is sufficient to call a domain malicious, or
even to flag it: length, entropy, digit ratio, vowel ratio, character
diversity, dictionary-word presence, hyphen structure, subdomain
depth and TLD are all combined into one composite score, and the
caller (detector.py) only raises a DNS-003 signal once that composite
crosses a configurable threshold. A domain's own query behaviour
(NXDOMAIN ratio, query volume) can further corroborate the score, but
is never required for it.

This intentionally replaces the previous "long label + low vowel
ratio -> DGA" one-shot heuristic, which flagged legitimate randomly
named subdomains (CDN edge nodes, hashed asset paths, etc.) far too
often.
"""

import math
from dataclasses import dataclass, field
from typing import Dict, Optional

# A short list of common English/technical words. Used only to check
# whether a label contains a *readable* substring, which lowers DGA
# suspicion -- this is not attempting to be an exhaustive dictionary.
COMMON_WORDS = {
    "www", "mail", "api", "app", "web", "cloud", "secure", "login",
    "account", "service", "update", "download", "content", "static",
    "cdn", "media", "images", "assets", "shop", "store", "news",
    "support", "help", "docs", "blog", "dev", "test", "staging",
    "prod", "admin", "portal", "auth", "gateway", "edge", "node",
    "server", "client", "data", "file", "files", "backup", "sync",
    "mobile", "search", "video", "photo", "market", "pay", "bank",
}

# Suspicious TLDs are a weak add-on signal only (see requirement:
# "suspicious TLD is a weak signal, not a verdict") -- at most 5 of
# the 100 possible points.
SUSPICIOUS_TLDS = {".top", ".xyz", ".click", ".gq", ".tk", ".ml", ".cf", ".ga", ".icu"}


@dataclass
class DGAScore:
    domain: str
    label: str
    score: int                       # 0-100 composite heuristic score
    confidence: str                  # confidence *in this heuristic result*
    signals: Dict[str, float] = field(default_factory=dict)
    explanation: str = ""


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _label_and_tld(domain: str):
    """The label evaluated for DGA-likeness is the leftmost part of the
    hostname -- for "qzxjklmpwvbnfgh.example.com" that's the queried
    subdomain "qzxjklmpwvbnfgh", not the registrable domain "example".
    For a bare two-label domain ("evil.top") this is the same as the
    registrable name."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) < 2:
        return parts[0] if parts else domain, "", parts
    tld = "." + parts[-1]
    label = parts[0]
    return label, tld, parts


def score_domain(domain: str, config: Optional[dict] = None,
                  nxdomain_ratio: float = 0.0, query_count: int = 1) -> DGAScore:
    """Compute a 0-100 composite DGA heuristic score for `domain`.

    `nxdomain_ratio` and `query_count` let behavioral context (from
    the aggregation layer) corroborate the lexical signals -- a
    high-entropy label that also produces a lot of NXDOMAIN responses
    is more consistent with DGA behaviour than the label alone.
    """
    cfg = (config or {}).get("dns", {}) if config else {}
    min_len = cfg.get("dga_min_label_length", 8)
    label, tld, parts = _label_and_tld(domain)

    if len(label) < min_len:
        return DGAScore(domain=domain, label=label, score=0, confidence="Low", signals={},
                         explanation=f"Label '{label}' is shorter than the "
                                     f"{min_len}-character minimum for DGA heuristics to apply.")

    signals: Dict[str, float] = {}

    # 1. Length (0-15): longer labels are more consistent with
    #    algorithmically generated strings, up to a saturation point.
    signals["length"] = round(min((len(label) - min_len) / 12.0, 1.0) * 15, 1)

    # 2. Entropy (0-25), normalized against the max possible entropy
    #    for the character set actually used in this label.
    entropy = _shannon_entropy(label)
    distinct = len(set(label))
    max_entropy = math.log2(distinct) if distinct > 1 else 1.0
    normalized_entropy = min(entropy / max(max_entropy, 1.0), 1.0)
    signals["entropy"] = round(normalized_entropy * 25 if entropy > 3.0 else (entropy / 3.0) * 15, 1)

    # 3. Digit ratio (0-15): DGA output frequently mixes in digits.
    digit_ratio = sum(1 for c in label if c.isdigit()) / len(label)
    signals["digit_ratio"] = round(min(digit_ratio / 0.3, 1.0) * 15, 1)

    # 4. Vowel ratio (0-15): pronounceable words/names have a vowel
    #    density well above what random character generation produces.
    vowel_ratio = sum(1 for c in label if c in "aeiou") / len(label)
    if vowel_ratio < 0.20:
        vowel_score = 15.0
    elif vowel_ratio < 0.35:
        vowel_score = 15.0 * (0.35 - vowel_ratio) / 0.15
    else:
        vowel_score = 0.0
    signals["vowel_ratio"] = round(max(0.0, min(vowel_score, 15.0)), 1)

    # 5. Character diversity (0-10): very repetitive strings and truly
    #    random strings both look different from typical hostnames.
    diversity = distinct / len(label)
    signals["char_diversity"] = round(min(diversity / 0.6, 1.0) * 10, 1)

    # 6. Dictionary word presence (-20..0): a readable substring
    #    substantially lowers suspicion (e.g. "api-gateway-3x7f").
    has_word = any(len(w) >= 3 and w in label for w in COMMON_WORDS)
    signals["dictionary_word"] = -20.0 if has_word else 0.0

    # 7. Hyphen structure (-5..+5): a couple of hyphens is typical of
    #    legitimate multi-word hostnames; excessive hyphenation is not.
    hyphen_count = label.count("-")
    if 0 < hyphen_count <= 2:
        signals["hyphen_structure"] = -5.0
    elif hyphen_count > 4:
        signals["hyphen_structure"] = 5.0
    else:
        signals["hyphen_structure"] = 0.0

    # 8. Subdomain depth (0-5): unusually deep subdomain chains are a
    #    mild corroborating signal (e.g. DNS-tunneling-style naming).
    signals["subdomain_depth"] = round(min(max(len(parts) - 2, 0), 3) / 3.0 * 5, 1)

    # 9. TLD (0-5): weak add-on only, per design -- never decisive alone.
    signals["tld"] = 5.0 if tld in SUSPICIOUS_TLDS else 0.0

    # 10. Behavioral corroboration (0-15): high NXDOMAIN ratio and
    #     high query volume are both consistent with DGA "beaconing".
    behavior_score = 0.0
    if nxdomain_ratio >= 0.5:
        behavior_score += 8.0
    if query_count >= 10:
        behavior_score += 7.0
    signals["behavior"] = behavior_score

    score = int(max(0, min(100, round(sum(signals.values())))))

    if score >= 70:
        confidence = "High"
    elif score >= 45:
        confidence = "Medium"
    else:
        confidence = "Low"

    explanation = (
        f"Label '{label}' scored {score}/100 across length, entropy "
        f"(H={entropy:.2f} bits), digit ratio ({digit_ratio:.0%}), vowel ratio "
        f"({vowel_ratio:.0%}) and character-diversity signals"
        + (", offset by a recognizable dictionary substring" if has_word else "")
        + (f", corroborated by a {nxdomain_ratio:.0%} NXDOMAIN ratio over {query_count} "
           f"quer{'y' if query_count == 1 else 'ies'}" if behavior_score else "")
        + ". This is a multi-signal heuristic, not a verdict — it should only "
          "drive severity when corroborated by independent evidence."
    )

    return DGAScore(domain=domain, label=label, score=score, confidence=confidence,
                     signals=signals, explanation=explanation)
