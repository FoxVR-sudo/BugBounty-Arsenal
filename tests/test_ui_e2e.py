import time
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:5000"


def run_ui_flow():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # Go to login
        page.goto(f"{BASE}/login", wait_until="domcontentloaded")
        page.wait_for_selector("text=Welcome back", timeout=10000)

        # Fill credentials and submit
        page.fill("input[name=email]", "test@example.com")
        page.fill("input[name=password]", "password")
        page.click("button[type=submit]")

        # Wait for dashboard to render scans and a Details button
        page.wait_for_selector("button:has-text('Details')", timeout=15000)

        # Click the first Details button
        page.click("button:has-text('Details')")

        # Wait for modal
        page.wait_for_selector("#scanDetailsModal", state="visible", timeout=10000)
        # Wait for timeline section to appear
        page.wait_for_selector("#detectorTimelineContent", timeout=5000)

        # Allow timeline to load
        time.sleep(1.0)
        html = page.inner_html('#detectorTimelineContent')
        assert html, "Timeline content empty"

        browser.close()
        return {"timeline_loaded": True}


if __name__ == "__main__":
    print("UI E2E OK:", run_ui_flow())
