# scope_parser.py
import csv
import re
from urllib.parse import urlparse

def parse_scope(csv_path):
    """
    Parse a scope CSV that may be either:
    - simple: rows like "URL,Status" where Status == "in" marks in-scope
    - rich: headered CSV (like the sample) which includes 'identifier' (URL or host)
      and 'eligible_for_submission' (true/false) to decide in/out-of-scope

    Returns two lists: (in_scope_list, out_scope_list) where each item is the
    raw identifier string from the CSV (URL, host or wildcard pattern).
    """
    in_scope = []
    out_scope = []

    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        # Peek first line to decide if headered
        first = csvfile.readline()
        csvfile.seek(0)
        has_header = ',' in first and not first.strip().lower().startswith('http')
        # Use DictReader when headered, otherwise simple reader
        if has_header:
            reader = csv.DictReader(csvfile)
            # Normalize header names to lower-case keys
            for row in reader:
                if not row:
                    continue
                # some CSVs use 'identifier' or 'url' as column name
                key = None
                for candidate in ('identifier', 'url', 'asset'):
                    if candidate in (k.lower() for k in row.keys()):
                        # find actual key name
                        for k in row.keys():
                            if k.lower() == candidate:
                                key = k
                                break
                        if key:
                            break
                if not key:
                    # fallback to first column
                    key = list(row.keys())[0]
                identifier = (row.get(key) or "").strip()
                # determine eligibility column
                elig = None
                for cand in ('eligible_for_submission', 'eligible_for_bounty', 'status'):
                    for k in row.keys():
                        if k.lower() == cand:
                            elig = (row.get(k) or "").strip().lower()
                            break
                    if elig is not None:
                        break
                # Decide in/out: treat 'true'/'yes'/'in' as in-scope
                is_in = False
                if elig is None:
                    # if no column, fallback to treat as in-scope
                    is_in = True
                else:
                    if elig in ('true', 'yes', 'in', '1'):
                        is_in = True
                    else:
                        is_in = False

                if identifier:
                    if is_in:
                        in_scope.append(identifier)
                    else:
                        out_scope.append(identifier)
        else:
            # simple CSV: URL,Status per row
            reader = csv.reader(csvfile)
            for row in reader:
                if not row or len(row) < 2:
                    continue
                url = row[0].strip()
                status = row[1].strip().lower()
                if status == "in":
                    in_scope.append(url)
                else:
                    out_scope.append(url)

    return in_scope, out_scope


def _normalize_prefix(p):
    # remove trailing slash for prefix matching consistency
    if not p:
        return p
    return p.rstrip('/')


def build_scope_matcher(in_scope_list):
    """
    Build and return a function is_in_scope(url) -> bool.

    Matching rules:
    - If an in_scope entry contains scheme (http/https), treat as URL prefix:
      url.startswith(prefix) (prefix normalized to remove trailing slash)
    - If entry contains a wildcard like 'test*.example.com', treat as glob against netloc
    - If entry looks like a domain (no scheme, may include '*'), match netloc:
        - exact host match OR subdomain match (netloc == domain or netloc.endswith('.' + domain))
        - wildcard '*' matches any chars in a single pattern (converted to regex)
    - If entry includes port, match netloc exactly (host:port)
    """
    prefixes = []
    domain_patterns = []  # tuples of (compiled_regex, raw_entry) matching netloc
    plain_domains = []

    for entry in in_scope_list:
        if not entry:
            continue
        e = entry.strip()
        parsed = urlparse(e if '://' in e else '//' + e)
        # if entry has scheme and netloc, treat as prefix
        if '://' in e or (parsed.scheme and parsed.netloc):
            prefixes.append(_normalize_prefix(e))
            continue

        # treat as domain or wildcard
        # wildcard handling
        if '*' in e:
            # build regex for netloc match: replace '*' -> '.*' (escape dots)
            pattern = '^' + re.escape(e).replace(r'\*', '.*') + '$'
            try:
                cre = re.compile(pattern, re.IGNORECASE)
                domain_patterns.append((cre, e))
            except re.error:
                # fallback to treat literal
                plain_domains.append(e.lower())
        else:
            plain_domains.append(e.lower())

    def is_in_scope(url):
        try:
            parsed = urlparse(url if '://' in url else '//' + url)
            full = _normalize_prefix(url)
            # check URL prefixes first
            for p in prefixes:
                if full.startswith(p):
                    return True
            netloc = (parsed.netloc or "").lower()
            if not netloc:
                return False
            # check wildcard patterns
            for cre, raw in domain_patterns:
                if cre.match(netloc):
                    return True
            # check plain domains and subdomains
            for d in plain_domains:
                if netloc == d:
                    return True
                if netloc.endswith('.' + d):
                    return True
            return False
        except Exception:
            return False

    return is_in_scope