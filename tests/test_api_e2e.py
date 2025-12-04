import time
import requests
from urllib.parse import urljoin

# Use local server
BASE = "http://127.0.0.1:5000"


def wait_server(timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            r = requests.get(BASE + "/", timeout=2)
            if r.status_code == 200:
                return True
        except Exception:
            time.sleep(0.5)
    return False


def ensure_test_user(session: requests.Session):
    # Attempt login first
    r = session.post(
        urljoin(BASE, "/api/login"),
        data={"email": "test@example.com", "password": "password"},
        timeout=10,
    )
    if r.status_code == 200:
        return True
    # If verification required, mark verified via internal helper endpoint if exists
    # Fallback: directly call DB through internal API not available here; rely on prior setup
    return False


def get_cookie(session: requests.Session, cookie_name: str):
    for c in session.cookies:
        if c.name == cookie_name:
            return c.value
    return None


def run_api_flow():
    assert wait_server(), "Server not responding on /"

    s = requests.Session()

    # Login
    r = s.post(urljoin(BASE, "/api/login"), data={"email": "test@example.com", "password": "password"}, timeout=10)
    assert r.status_code == 200, f"Login failed: {r.status_code} {r.text}"
    assert get_cookie(s, "access_token") is not None, "No access_token cookie set"

    # Start a recon scan
    r = s.post(urljoin(BASE, "/scan"), data={"mode": "recon", "recon_domain": "httpbin.org"}, allow_redirects=False, timeout=20)
    assert r.status_code in (302, 303), f"Start scan failed: {r.status_code} {r.text}"

    # Discover the latest job_id via scan-status
    r = s.get(urljoin(BASE, "/scan-status"), timeout=10)
    assert r.status_code == 200, f"scan-status failed: {r.status_code}"
    data = r.json()
    scans = data.get("scans", [])
    assert len(scans) > 0, "No scans returned for user"
    job_id = scans[0]["job_id"]

    # Poll progress a few times
    for _ in range(6):
        pr = s.get(urljoin(BASE, f"/api/scan/{job_id}/progress"), timeout=10)
        if pr.status_code == 200:
            pj = pr.json()
            if pj.get("status") and pj.get("status") != "running":
                break
        time.sleep(2)

    # Check details, timeline, findings endpoints
    dr = s.get(urljoin(BASE, f"/api/scan/{job_id}/details"), timeout=10)
    assert dr.status_code == 200, f"details failed: {dr.status_code}"

    tr = s.get(urljoin(BASE, f"/api/scan/{job_id}/detector-timeline"), timeout=10)
    assert tr.status_code == 200, f"timeline failed: {tr.status_code}"
    tj = tr.json()
    assert "timeline" in tj, "timeline shape invalid"

    fr = s.get(urljoin(BASE, f"/api/scan/{job_id}/findings"), timeout=10)
    assert fr.status_code in (200, 404), f"findings unexpected: {fr.status_code}"

    return {
        "job_id": job_id,
        "timeline_total": tj.get("total", 0),
    }


if __name__ == "__main__":
    out = run_api_flow()
    print("API E2E OK:", out)
