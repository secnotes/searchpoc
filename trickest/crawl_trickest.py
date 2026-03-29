#!/usr/bin/env python3
"""
Trickest CVE References Crawler
Downloads CVE references from trickest/cve GitHub repository and converts to JSON format.

Usage:
    python3 crawl_trickest.py <output_filename>
    python3 crawl_trickest.py trickest_cve.json
    python3 crawl_trickest.py trickest_cve.json --output-dir trickest
"""

import argparse
import json
import os
import re
import sys

try:
    from urllib.request import urlopen, Request, ProxyHandler, build_opener
    from urllib.error import URLError, HTTPError
except ImportError:
    print("Error: urllib not available")
    sys.exit(1)


DEFAULT_URL = "https://raw.githubusercontent.com/trickest/cve/main/references.txt"
DEFAULT_PROXY = "192.168.17.1:10808"


def download_references(url=DEFAULT_URL, proxy=None):
    """Download references.txt from GitHub"""
    print(f"Downloading from: {url}")

    if proxy:
        print(f"Using proxy: {proxy}")

    try:
        request = Request(url, headers={'User-Agent': 'Mozilla/5.0'})

        if proxy:
            proxy_handler = ProxyHandler({
                'http': proxy,
                'https': proxy
            })
            opener = build_opener(proxy_handler)
            response = opener.open(request, timeout=120)
        else:
            response = urlopen(request, timeout=120)

        content = response.read().decode('utf-8')
        lines_count = len(content.splitlines())
        print(f"Downloaded {len(content):,} bytes ({lines_count:,} lines)")
        return content
    except HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.reason}")
        sys.exit(1)
    except URLError as e:
        print(f"URL Error: {e.reason}")
        print("Please check your network connection or try using --proxy option.")
        sys.exit(1)
    except Exception as e:
        print(f"Error downloading file: {e}")
        sys.exit(1)


def parse_references(content):
    """
    Parse references.txt content and extract CVE-PoC pairs.

    Format of references.txt (trickest/cve):
    Each line contains: CVE-ID - reference_url
    Example: CVE-2021-44228 - https://github.com/example/log4j-poc
    """
    data = []
    lines = content.strip().split('\n')

    # Regex pattern to match: CVE-ID - URL
    # Format: CVE-YYYY-NNNN - https://...
    line_pattern = re.compile(r'(CVE-\d{4}-\d{4,})\s*-\s*(https?://\S+)', re.IGNORECASE)

    for line in lines:
        line = line.strip()
        if not line:
            continue

        match = line_pattern.match(line)
        if match:
            cve_id = match.group(1).upper()
            poc_url = match.group(2).strip()

            if poc_url:
                data.append({
                    "CVE": cve_id,
                    "PoC": poc_url
                })

    return data


def save_to_json(data, output_path):
    """Save parsed data to JSON file"""
    # Ensure directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    # Count unique CVEs
    unique_cves = len(set(item['CVE'] for item in data))

    print(f"\nSaved to: {output_path}")
    print(f"Total PoC entries: {len(data):,}")
    print(f"Unique CVEs: {unique_cves:,}")


def main():
    parser = argparse.ArgumentParser(
        description='Download CVE references from trickest/cve and convert to JSON'
    )
    parser.add_argument(
        'output',
        help='Output JSON file name (e.g., trickest_cve.json)'
    )
    parser.add_argument(
        '--url',
        default=DEFAULT_URL,
        help=f'Custom URL for references.txt (default: {DEFAULT_URL})'
    )
    parser.add_argument(
        '--output-dir',
        default='trickest',
        help='Output directory (default: trickest)'
    )
    parser.add_argument(
        '--proxy',
        default=None,
        help=f'HTTP/HTTPS proxy (e.g., {DEFAULT_PROXY})'
    )

    args = parser.parse_args()

    # Construct full output path
    output_path = os.path.join(args.output_dir, args.output)

    # Download
    content = download_references(args.url, args.proxy)

    # Parse
    print("Parsing references...")
    data = parse_references(content)

    if not data:
        print("No valid CVE-PoC entries found!")
        sys.exit(1)

    # Save
    save_to_json(data, output_path)

    print("Done!")


if __name__ == "__main__":
    main()