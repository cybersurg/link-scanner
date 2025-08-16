# Link Scanner (VirusTotal)

A Chrome extension that lets you right-click any link or paste a URL to instantly check if it's Safe, Suspicious, or Malicious using VirusTotal.

## Features
- Right-click a link → "Scan link with Link Scanner".
- Paste a URL in the popup and hit Scan.
- Color-coded verdicts with malicious/suspicious/harmless counts.
- Stores last scan result locally.
- Privacy-friendly: only scans when you ask.

## Requirements
- Chrome browser (Manifest V3 support).
- A free VirusTotal API key (get one at https://www.virustotal.com/gui/join-us).

## Installation
1. Clone this repo or download the ZIP.
2. Go to `chrome://extensions`, enable Developer Mode.
3. Click "Load unpacked" and select the extension folder.
4. Open the extension's Options page and paste your VirusTotal API key.

## Privacy Policy
This extension does not collect, store, or sell personal data. URLs are sent to VirusTotal only when the user initiates a scan.

## License
MIT License
