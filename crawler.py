# crawler.py
# Async crawler / parameter & form discovery using BeautifulSoup for robust HTML parsing.
from urllib.parse import urljoin
from bs4 import BeautifulSoup

async def discover_params(session, url):
    """
    Return dict:
      {
        "forms": [
            {"action": "<absolute url>", "method": "get|post", "inputs": ["name1","name2", ...]},
            ...
        ],
        "links": [ "<absolute href>", ... ]
      }
    Uses BeautifulSoup to extract form action/method and input/select/textarea names.
    """
    result = {"forms": [], "links": []}
    try:
        async with session.get(url, allow_redirects=True) as resp:
            try:
                text = await resp.text()
            except Exception:
                return result

            soup = BeautifulSoup(text, "lxml")

            # forms: extract action (absolute), method, and input names
            for form in soup.find_all("form"):
                action = form.get("action") or ""
                action = urljoin(url, action)
                method = (form.get("method") or "get").strip().lower()
                inputs = set()
                # input, textarea, select
                for tag in form.find_all(["input", "textarea", "select"]):
                    name = tag.get("name")
                    if name:
                        inputs.add(name)
                result["forms"].append({
                    "action": action,
                    "method": method,
                    "inputs": list(inputs)
                })

            # href links (basic)
            hrefs = []
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("javascript:"):
                    continue
                hrefs.append(urljoin(url, href))
            result["links"] = list(dict.fromkeys(hrefs))  # preserve unique

    except Exception:
        # on any parsing / request error, return whatever we have
        pass
    return result