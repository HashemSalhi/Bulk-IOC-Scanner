"""Auto-detect the type of an indicator of compromise."""
import re

# Pre-compiled patterns (order matters — most specific first)
_MD5 = re.compile(r'^[a-fA-F0-9]{32}$')
_SHA1 = re.compile(r'^[a-fA-F0-9]{40}$')
_SHA256 = re.compile(r'^[a-fA-F0-9]{64}$')

# Single IPv4 address
_IPV4 = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')

# IPv4 CIDR range, e.g. 192.168.0.0/24
_CIDR = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$')

# URL: must start with http/https/ftp (or defanged hxxp)
_URL = re.compile(
    r'^(?:hxxps?|https?|ftp)(?:\[://\]|://).+',
    re.IGNORECASE,
)

# Email address
_EMAIL = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

# CVE identifier, e.g. CVE-2021-44228
_CVE = re.compile(r'^CVE-\d{4}-\d{4,7}$', re.IGNORECASE)

# Autonomous System Number, e.g. AS15169 or ASN15169
_ASN = re.compile(r'^AS(?:N)?\d{1,10}$', re.IGNORECASE)

# Bitcoin (legacy P2PKH/P2SH base58 + bech32) and Ethereum addresses
_BTC = re.compile(r'^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,39}|bc1[a-z0-9]{25,59})$')
_ETH = re.compile(r'^0x[a-fA-F0-9]{40}$')

# Domain: no path, no protocol, has at least one dot
_DOMAIN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


def refang(ioc: str) -> str:
    """
    Convert a defanged IOC back to its real form so it can be sent to providers.
    Handles the common analyst defang styles, e.g.:
      8[.]8[.]8[.]8   -> 8.8.8.8
      evil(.)com      -> evil.com
      hxxps://bad/x   -> https://bad/x
      hxxp[://]bad    -> http://bad
    """
    ioc = ioc.strip()
    # Scheme defang (only at the start, so we don't corrupt substrings like "hxxption")
    ioc = re.sub(r'^hxxp', 'http', ioc, flags=re.IGNORECASE)
    # Dot defang variants
    ioc = ioc.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    ioc = re.sub(r'\[dot\]', '.', ioc, flags=re.IGNORECASE)
    # At-sign defang (emails): user[at]domain -> user@domain
    ioc = re.sub(r'\[at\]|\(at\)', '@', ioc, flags=re.IGNORECASE)
    # Scheme separator defang
    ioc = ioc.replace("[://]", "://").replace("[:]", ":")
    return ioc


def detect(ioc: str) -> str:
    """
    Return one of: 'md5', 'sha1', 'sha256', 'ip', 'cidr', 'domain', 'url',
    'email', 'cve', 'asn', 'crypto', or 'unknown'. Defanging is tolerated.
    """
    ioc = refang(ioc)
    if not ioc:
        return "unknown"

    # Hashes (Ethereum 0x-addresses are 42 chars, so they won't collide with sha1)
    if _SHA256.match(ioc):
        return "sha256"
    if _SHA1.match(ioc):
        return "sha1"
    if _MD5.match(ioc):
        return "md5"

    if _URL.match(ioc):
        return "url"
    if _EMAIL.match(ioc):
        return "email"
    if _CVE.match(ioc):
        return "cve"
    if _ASN.match(ioc):
        return "asn"
    if _ETH.match(ioc) or _BTC.match(ioc):
        return "crypto"
    if _CIDR.match(ioc):
        return "cidr"
    if _IPV4.match(ioc):
        return "ip"
    if _DOMAIN.match(ioc):
        return "domain"

    return "unknown"


def parse_bulk_input(text: str) -> list[str]:
    """Split pasted text on newlines and commas, strip whitespace, drop blanks."""
    raw = re.split(r'[\n,]+', text)
    return [item.strip() for item in raw if item.strip()]
