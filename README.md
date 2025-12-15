I built a Chrome Extension (Manifest V3) that allows a user to enter an IP address and retrieve OSINT information from VirusTotal, IPinfo, and AbuseIPDB, without using official APIs.

The extension uses Chrome DevTools Protocol (CDP) via chrome.debugger to automate browser navigation and extract information from the rendered pages.

How it works

The user opens the extension popup and enters an IP address.

The popup sends a message to the background service worker.

The service worker creates background (inactive) tabs for each data source.

Using CDP, the service worker:

Navigates to the target pages

Extracts data from the DOM / visible text

The collected data is aggregated into a single result object.

Results are stored in chrome.storage.local and returned to the popup.

The popup displays a summary and a detailed card for each source.

Design decisions

No visible tabs: All tabs are opened with active: false so the popup stays open and the UX is not interrupted.

Best-effort scraping:

VirusTotal: visible text + Shadow DOM traversal

IPinfo: section-based text parsing (Summary / Geolocation)

AbuseIPDB: structured DOM extraction (tables, reports, confidence score)

User-action fallback:
If a site blocks automation (cookies, Cloudflare, login), the extension returns a requires_user_action state with a URL and instructions.

Challenges & solutions

Bot protection / cookie banners
→ Detect challenge pages and return a clear requires_user_action response.
→ Automatically accept cookies on AbuseIPDB when possible.

Dynamic and Shadow DOM content
→ Implemented a recursive visible-text collector that also walks Shadow DOM.

Presenting complex data clearly
→ Added a top summary (risk level, ASN, location) and clean source cards with “Open” and “Copy JSON” actions.

What’s included

background.js: CDP automation, scraping logic, and data aggregation

popup.js: UI rendering, summary computation, and user interactions

Results stored locally and reloaded when reopening the popup
