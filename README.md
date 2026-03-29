# CVE PoC Search Engine

[English](README.md) | [中文](README_CN.md)

A modern, standalone HTML-based search engine for CVE Proof of Concept (PoC) exploits. **Almost every publicly available CVE PoC is included.**

## Features

- **Modern UI Design**: Dark/Light theme toggle with gradient backgrounds
- **Standalone HTML**: No server required, works directly in browser
- **Fast Search**: Instant search by CVE ID (press Enter or click Search button)
- **Multiple Data Sources**: Combines data from multiple JSON sources
- **Responsive Design**: Works on desktop and mobile devices
- **Theme Persistence**: Remembers user's theme preference

## Usage

### Generate Search Page

Run the generator script to create the HTML search page:

```bash
python3 generate_search.py
```

This will:
1. Load CVE data from all sources defined in `config.json`
2. Generate `search/index.html` with embedded data
3. Display statistics (total CVE entries and PoC links)

### Open the Search Page

Simply open `search/index.html` in your browser:
- Double-click the file
- Or use: `firefox search/index.html`

### Search for CVE

1. Enter a CVE ID (e.g., `CVE-2024-1234` or just `2024`)
2. Press Enter or click the Search button
3. Results will show CVE ID with PoC links

## Configuration

Edit `config.json` to add/remove data sources:

```json
{
  "sources": [
    "unsafe/cve_poc_unsafe.json",
    "trickest/trickest_cve.json"
  ]
}
```

## Data Format

JSON files should follow this format:

```json
[
  {"CVE": "CVE-2021-44228", "PoC": "https://github.com/example/log4j-poc"},
  {"CVE": "CVE-2021-44228", "PoC": "https://github.com/another/log4j-demo"},
  ...
]
```

## Statistics

Current data includes:
- **118,304** CVE entries
- **175,786** PoC links

## Sources

- [trickest/cve](https://github.com/trickest/cve) - Comprehensive CVE references collection
- Custom PoC collections

## License

This project is for educational and security research purposes only.

## Disclaimer

Use these PoC resources responsibly. Only test on systems you own or have explicit permission to test. Unauthorized use of exploits may be illegal.