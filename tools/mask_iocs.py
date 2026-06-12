#!/usr/bin/env python3
"""Single shared IOC-masking implementation (roadmap F1.9).

mask_iocs(text) -> str replaces real IOCs with type tokens so models learn
the *kind* of content instead of memorising rotating indicators:

    ip -> <IP>   url -> <URL>   domain -> <DOMAIN>   hash -> <HASH>
    email -> <EMAIL>   cve -> <CVE>   crypto_wallet -> <WALLET>
    credential (user:pass) -> <CRED>

The regexes, placeholder lists and rejection logic are ported VERBATIM from
tools/noctis_rules.py (the rules layer is the single source of truth for what
counts as an IOC; F1.9 forbids a second masking implementation). The IOC type
set is exactly the one noctis_rules.extract_iocs produces: url, email, cve,
hash_sha256, hash_sha1, hash_md5, crypto_wallet, ip, domain, credential —
the three hash kinds all map to the single <HASH> token.

Ordering mirrors extract_iocs: URLs and e-mails are masked FIRST so their
remnants cannot re-match as domains or user:pass pairs; then cve, hashes
(longest first), wallets, ips, domains; credential pairs run last. Unlike
extract_iocs (which findall()s every type against one masked string), masking
substitutes progressively, so e.g. "1.2.3.4:8080" becomes "<IP>:8080" rather
than also matching the credential regex — placeholder rejection semantics are
identical.

Placeholders are NOT masked: "http://example.com" or "user:pass" are example
prose, not indicators, and stay verbatim (same rejection sets as
noctis_rules.py).

This module touches no database — it is a pure function meant to be imported
by build_dataset.py (training) and any future serving path (§6.1); train/serve
skew here silently ruins the model. The CLI below is only for spot checks.

CRITICAL: this same function must be applied at inference time (§6.1).

Usage:
    from mask_iocs import mask_iocs
    masked = mask_iocs("слив базы mark:opensesame на 91.92.93.94")
    # -> "слив базы <CRED> на <IP>"

Examples:
    # spot-check a string
    python3 tools/mask_iocs.py --text "C2 at 91.92.93.94, combo bob:hunter22"

    # mask stdin line by line
    cat samples.txt | python3 tools/mask_iocs.py
"""

import re

# --------------------------------------------------------------------------
# Placeholder lists — ported verbatim from tools/noctis_rules.py.
# Conservative on purpose: when in doubt, do NOT treat as placeholder.
# --------------------------------------------------------------------------
PLACEHOLDER_DOMAINS = {
    "example.com", "example.org", "example.net", "example.edu",
    "test.com", "test.net", "domain.com", "yourdomain.com", "sample.com",
    "site.com", "mysite.com", "foo.com", "bar.com", "foobar.com",
    "acme.com", "company.com", "yourcompany.com", "localhost",
    "domain.tld", "email.tld", "website.com",
}
# Reserved documentation ranges (RFC 5737) + classic examples.
PLACEHOLDER_IPS = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "1.1.1.1", "8.8.8.8", "8.8.4.4", "1.2.3.4",
}
PLACEHOLDER_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.",
                           "10.", "192.168.", "172.16.")
# Email local parts that give away a placeholder.
PLACEHOLDER_EMAIL_LOCAL = {
    "user", "test", "email", "your", "youremail", "name", "username",
    "example", "admin", "john.doe", "jane.doe", "foo", "bar", "noreply",
}
PLACEHOLDER_EMAIL_DOMAINS = PLACEHOLDER_DOMAINS  # same dummy-domain set
# Tokens that mark a user:pass pair as an EXAMPLE, not a real credential.
PH_USER_TOKENS = {"user", "username", "login", "email", "your_email",
                  "youremail", "name", "usuario", "admin", "uname"}
PH_PASS_TOKENS = {"pass", "password", "passwd", "your_password", "yourpassword",
                  "changeme", "contrasena", "clave", "secret", "1234", "12345",
                  "123456", "examplepass", "test"}

# --------------------------------------------------------------------------
# IOC regexes — ported verbatim from tools/noctis_rules.py.
# Hash order: check the longest first.
# --------------------------------------------------------------------------
RE_URL    = re.compile(r"\b(?:https?|hxxps?|ftp)://[^\s<>\"')]+", re.I)
RE_EMAIL  = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", re.I)
RE_IPV4   = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                       r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
                       r"[a-z]{2,24}\b", re.I)
RE_CVE    = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
RE_SHA1   = re.compile(r"\b[a-f0-9]{40}\b", re.I)
RE_MD5    = re.compile(r"\b[a-f0-9]{32}\b", re.I)
RE_ETH    = re.compile(r"\b0x[a-f0-9]{40}\b", re.I)
RE_BTC    = re.compile(r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")

# A generic user:pass credential pair (with or without spaces).
RE_CREDPAIR = re.compile(r"\b([A-Za-z0-9._\-]{2,64})\s*:\s*([^\s:@]{3,64})\b")


def is_placeholder_ioc(kind: str, value: str) -> bool:
    """True if the IOC is a placeholder/example and must not be masked."""
    v = value.lower().rstrip(".,);]")
    if kind == "domain":
        return v in PLACEHOLDER_DOMAINS or v.endswith(".local") or v.endswith(".test")
    if kind == "url":
        host = re.sub(r"^[a-z]+://", "", v).split("/")[0].split(":")[0]
        return host in PLACEHOLDER_DOMAINS or host in PLACEHOLDER_IPS
    if kind == "ip":
        return v in PLACEHOLDER_IPS or v.startswith(PLACEHOLDER_IP_PREFIXES)
    if kind == "email":
        local, _, dom = v.partition("@")
        return local in PLACEHOLDER_EMAIL_LOCAL or dom in PLACEHOLDER_EMAIL_DOMAINS
    if kind.startswith("hash") or kind == "crypto_wallet":
        # degenerate hashes (all zeros, a single repeated character)
        body = v[2:] if v.startswith("0x") else v
        return len(set(body)) <= 1
    return False


def is_placeholder_cred(user: str, pwd: str) -> bool:
    """True if user:pass is an EXAMPLE (dummy tokens), not a real credential."""
    return user.lower() in PH_USER_TOKENS or pwd.lower() in PH_PASS_TOKENS


def _sub_ioc(pattern: re.Pattern, kind: str, token: str, text: str) -> str:
    """Replace non-placeholder matches of pattern with token."""
    def repl(m: re.Match) -> str:
        return m.group(0) if is_placeholder_ioc(kind, m.group(0)) else token
    return pattern.sub(repl, text)


def mask_iocs(text: str) -> str:
    """Replace every real IOC in text with its type token; placeholders stay.

    Deterministic and idempotent: tokens contain no maskable substrings, so
    mask_iocs(mask_iocs(x)) == mask_iocs(x).
    """
    if not text:
        return text or ""

    # 1) URLs and e-mails first — mirrors the extract_iocs masking trick so
    #    their remnants never re-match as domains or credential pairs.
    out = _sub_ioc(RE_URL, "url", "<URL>", text)
    out = _sub_ioc(RE_EMAIL, "email", "<EMAIL>", out)

    # 2) Remaining types in extract_iocs order, longest hash first.
    out = _sub_ioc(RE_CVE, "cve", "<CVE>", out)
    out = _sub_ioc(RE_SHA256, "hash_sha256", "<HASH>", out)
    out = _sub_ioc(RE_SHA1, "hash_sha1", "<HASH>", out)
    out = _sub_ioc(RE_MD5, "hash_md5", "<HASH>", out)
    out = _sub_ioc(RE_ETH, "crypto_wallet", "<WALLET>", out)
    out = _sub_ioc(RE_BTC, "crypto_wallet", "<WALLET>", out)
    out = _sub_ioc(RE_IPV4, "ip", "<IP>", out)
    out = _sub_ioc(RE_DOMAIN, "domain", "<DOMAIN>", out)

    # 3) Credential pairs last, with the verbatim noctis_rules rejections:
    #    numeric users, path-like passwords, and placeholder tokens stay.
    #    Port note: extract_iocs replaces URLs/e-mails with spaces before
    #    credential detection, so "leak: <URL>" can never arise there. Here
    #    masking substitutes tokens instead, so a password side starting
    #    with "<" is one of our own mask tokens, never a real credential.
    def cred_repl(m: re.Match) -> str:
        u, p = m.group(1), m.group(2)
        if u.isdigit() or p.startswith(("/", "<")) or is_placeholder_cred(u, p):
            return m.group(0)
        return "<CRED>"
    out = RE_CREDPAIR.sub(cred_repl, out)

    return out


if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        description="Spot-check the shared IOC masker (F1.9). Reads --text "
                    "or stdin; no DB access.",
        epilog=__doc__.split("Examples:")[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--text", help="mask a single string and exit")
    args = ap.parse_args()

    if args.text is not None:
        print(mask_iocs(args.text))
    else:
        for line in sys.stdin:
            print(mask_iocs(line.rstrip("\n")))
