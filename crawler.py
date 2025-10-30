# crawler.py
# Lightweight async crawler / parameter discovery (ASCII-only to avoid encoding errors).
import re
from urllib.parse import urljoin

async def discover_params(session, url):
    """
    Return dict: {"forms": [names], "links": [hrefs]}
    No JS evaluation - simple HTML parsing using regex.
    """
    result = {"forms": [], "links": []}
    try:
        async with session.get(url, allow_redirects=True) as resp:
            try:
                text = await resp.text()
            except Exception:
                return result

            # form input name attributes
            inputs = re.findall(r'<input[^>]+name=["\']?([\w\-\[\]]+)["\']?', text, re.IGNORECASE)
            result["forms"] = list(set(inputs))

            # href links (basic)
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', text, re.IGNORECASE)
            hrefs = [urljoin(url, h) for h in hrefs if not h.startswith("javascript:")]
            result["links"] = list(set(hrefs))
    except Exception:
        pass
    return result