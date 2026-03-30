#!/usr/bin/env python3
"""
CVE PoC Search Engine Generator
Generates a modern HTML search engine for CVE PoC lookups
"""

import json
import os
from datetime import datetime


def load_config(config_path="config.json"):
    """Load configuration from config.json"""
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    # Store the config directory for resolving relative paths
    config['_config_dir'] = os.path.dirname(config_path)
    return config


def load_cve_data(config):
    """Load all CVE data from configured sources"""
    cve_dict = {}
    config_dir = config.get('_config_dir', '')

    for source in config.get('sources', []):
        # Resolve path relative to config directory
        if not os.path.isabs(source):
            source = os.path.join(config_dir, source)

        if not os.path.exists(source):
            print(f"Warning: Source file not found: {source}")
            continue

        with open(source, 'r', encoding='utf-8') as f:
            data = json.load(f)

        for item in data:
            cve_id = item.get('CVE', '').upper()
            poc_url = item.get('PoC', '')

            if cve_id and poc_url:
                if cve_id not in cve_dict:
                    cve_dict[cve_id] = []
                cve_dict[cve_id].append(poc_url)

    return cve_dict


def generate_html(cve_data, output_path="index.html"):
    """Generate modern HTML search engine"""

    # Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # Convert to compact JSON for JS (no indent, minimal size)
    cve_json = json.dumps(cve_data, ensure_ascii=False, separators=(',', ':'))
    total_cves = len(cve_data)
    total_pocs = sum(len(v) for v in cve_data.values())

    html_content = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVE PoC Search Engine</title>
    <style>
        :root {
            --bg-gradient: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --text-muted: #888;
            --text-faint: #666;
            --text-footer: #555;
            --bg-card: rgba(255, 255, 255, 0.03);
            --bg-card-hover: rgba(255, 255, 255, 0.06);
            --bg-stat: rgba(255, 255, 255, 0.05);
            --bg-input: rgba(255, 255, 255, 0.05);
            --bg-input-focus: rgba(255, 255, 255, 0.08);
            --bg-poc: rgba(124, 58, 237, 0.15);
            --bg-poc-hover: rgba(124, 58, 237, 0.25);
            --bg-tag: rgba(244, 114, 182, 0.2);
            --border-card: rgba(255, 255, 255, 0.08);
            --border-stat: rgba(255, 255, 255, 0.1);
            --border-input: rgba(255, 255, 255, 0.1);
            --border-hover: rgba(0, 212, 255, 0.3);
            --border-poc: #7c3aed;
            --color-highlight: #00d4ff;
            --color-poc: #a78bfa;
            --color-poc-hover: #c4b5fd;
            --color-tag: #f472b6;
            --color-hot-tag: #a0a0a0;
            --color-input: #fff;
            --placeholder: #666;
            --shadow-input: rgba(0, 212, 255, 0.2);
        }

        [data-theme="light"] {
            --bg-gradient: linear-gradient(135deg, #f0f4f8 0%, #e8ecf0 50%, #dce2e8 100%);
            --text-primary: #1a1a2e;
            --text-secondary: #4a4a5e;
            --text-muted: #6a6a7e;
            --text-faint: #8a8a9e;
            --text-footer: #9a9aae;
            --bg-card: rgba(0, 0, 0, 0.02);
            --bg-card-hover: rgba(0, 0, 0, 0.04);
            --bg-stat: rgba(0, 0, 0, 0.03);
            --bg-input: rgba(255, 255, 255, 0.8);
            --bg-input-focus: rgba(255, 255, 255, 0.95);
            --bg-poc: rgba(124, 58, 237, 0.08);
            --bg-poc-hover: rgba(124, 58, 237, 0.15);
            --bg-tag: rgba(124, 58, 237, 0.15);
            --border-card: rgba(0, 0, 0, 0.06);
            --border-stat: rgba(0, 0, 0, 0.08);
            --border-input: rgba(0, 0, 0, 0.1);
            --border-hover: rgba(0, 150, 200, 0.4);
            --border-poc: #7c3aed;
            --color-highlight: #0080a0;
            --color-poc: #6d28d9;
            --color-poc-hover: #5b21b6;
            --color-tag: #7c3aed;
            --color-hot-tag: #4a4a5e;
            --color-input: #1a1a2e;
            --placeholder: #8a8a9e;
            --shadow-input: rgba(0, 150, 200, 0.15);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: var(--bg-gradient);
            min-height: 100vh;
            color: var(--text-primary);
            transition: background 0.3s ease, color 0.3s ease;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 40px 20px;
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
            position: relative;
        }

        .theme-toggle {
            position: absolute;
            top: 0;
            right: 0;
            padding: 8px 12px;
            background: var(--bg-stat);
            border: 1px solid var(--border-stat);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            color: var(--text-muted);
            font-size: 0.85rem;
        }

        .theme-toggle:hover {
            border-color: var(--color-highlight);
            color: var(--color-highlight);
        }

        .theme-icon {
            width: 16px;
            height: 16px;
        }

        .header h1 {
            font-size: 2.5rem;
            background: linear-gradient(90deg, #00d4ff, #7c3aed, #f472b6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }

        .header p {
            color: var(--text-secondary);
            font-size: 1.1rem;
        }

        .stats {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 20px;
        }

        .stat-item {
            text-align: center;
            padding: 15px 25px;
            background: var(--bg-stat);
            border-radius: 12px;
            border: 1px solid var(--border-stat);
        }

        .stat-number {
            font-size: 1.8rem;
            font-weight: bold;
            color: var(--color-highlight);
        }

        .stat-label {
            font-size: 0.9rem;
            color: var(--text-muted);
            margin-top: 5px;
        }

        .search-container {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
        }

        .search-wrapper {
            position: relative;
            flex: 1;
        }

        .search-box {
            width: 100%;
            padding: 18px 20px 18px 50px;
            font-size: 1.1rem;
            border: 2px solid var(--border-input);
            border-radius: 16px;
            background: var(--bg-input);
            color: var(--color-input);
            outline: none;
            transition: all 0.3s ease;
        }

        .search-box:focus {
            border-color: var(--color-highlight);
            background: var(--bg-input-focus);
            box-shadow: 0 0 20px var(--shadow-input);
        }

        .search-box::placeholder {
            color: var(--placeholder);
        }

        .search-icon {
            position: absolute;
            left: 18px;
            top: 50%;
            transform: translateY(-50%);
            width: 20px;
            height: 20px;
            opacity: 0.5;
            pointer-events: none;
        }

        .search-btn {
            padding: 18px 30px;
            font-size: 1.1rem;
            font-weight: 600;
            border: none;
            border-radius: 16px;
            background: linear-gradient(135deg, #00d4ff, #7c3aed);
            color: #fff;
            cursor: pointer;
            transition: all 0.3s ease;
            white-space: nowrap;
        }

        .search-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(0, 212, 255, 0.3);
        }

        .search-btn:active {
            transform: translateY(0);
        }

        .results-info {
            padding: 10px 0;
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        .results-container {
            display: grid;
            gap: 15px;
        }

        .result-card {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 12px;
            padding: 20px;
            transition: all 0.3s ease;
        }

        .result-card:hover {
            background: var(--bg-card-hover);
            border-color: var(--border-hover);
            transform: translateY(-2px);
        }

        .cve-id {
            font-size: 1.3rem;
            font-weight: 600;
            color: var(--color-highlight);
            margin-bottom: 12px;
            font-family: 'Consolas', 'Monaco', monospace;
        }

        .poc-links {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .poc-link {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 15px;
            background: var(--bg-poc);
            border-radius: 8px;
            text-decoration: none;
            color: var(--color-poc);
            transition: all 0.2s ease;
            border: 1px solid transparent;
        }

        .poc-link:hover {
            background: var(--bg-poc-hover);
            border-color: var(--border-poc);
            color: var(--color-poc-hover);
        }

        .poc-link::before {
            content: "→";
            font-weight: bold;
        }

        .poc-link span {
            word-break: break-all;
            line-height: 1.4;
        }

        .no-results {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-faint);
        }

        .no-results h3 {
            font-size: 1.3rem;
            margin-bottom: 10px;
            color: var(--text-muted);
        }

        .tag {
            display: inline-block;
            padding: 3px 8px;
            background: var(--bg-tag);
            color: var(--color-tag);
            border-radius: 4px;
            font-size: 0.75rem;
            margin-left: 10px;
        }

        .footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: var(--text-footer);
            font-size: 0.85rem;
        }

        .footer a {
            color: var(--color-highlight);
            text-decoration: none;
        }

        .footer a:hover {
            text-decoration: underline;
        }

        .footer p {
            margin: 5px 0;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        .separator {
            color: var(--text-faint);
        }

        .github-link {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            text-decoration: none;
        }

        .github-link:hover {
            text-decoration: none;
        }

        .github-icon {
            width: 16px;
            height: 16px;
        }

        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
            margin-top: 30px;
            flex-wrap: wrap;
        }

        .pagination button {
            padding: 8px 16px;
            background: var(--bg-stat);
            border: 1px solid var(--border-stat);
            border-radius: 8px;
            color: var(--text-primary);
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .pagination button:hover:not(:disabled) {
            border-color: var(--color-highlight);
            color: var(--color-highlight);
        }

        .pagination button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .pagination .page-info {
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        .pagination .page-numbers {
            display: flex;
            gap: 5px;
        }

        .pagination .page-num {
            padding: 8px 12px;
            background: var(--bg-stat);
            border: 1px solid var(--border-stat);
            border-radius: 6px;
            color: var(--text-muted);
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .pagination .page-num:hover {
            border-color: var(--color-highlight);
            color: var(--color-highlight);
        }

        .pagination .page-num.active {
            background: var(--color-highlight);
            color: #fff;
            border-color: var(--color-highlight);
        }

        @media (max-width: 600px) {
            .header h1 {
                font-size: 1.8rem;
            }

            .stats {
                flex-direction: column;
                gap: 15px;
            }

            .search-container {
                flex-direction: column;
            }

            .search-box {
                font-size: 1rem;
            }

            .search-btn {
                padding: 15px 20px;
            }

            .theme-toggle {
                position: static;
                margin-bottom: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <button class="theme-toggle" id="themeToggle">
                <svg class="theme-icon" id="themeIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="5"></circle>
                    <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"></path>
                </svg>
                <span id="themeText">Light</span>
            </button>
            <h1>CVE PoC Search Engine</h1>
            <p>Almost every publicly available CVE PoC is included</p>
            <div class="stats">
                <div class="stat-item">
                    <div class="stat-number">''' + f"{total_cves:,}" + '''</div>
                    <div class="stat-label">CVE Entries</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">''' + f"{total_pocs:,}" + '''</div>
                    <div class="stat-label">PoC Links</div>
                </div>
            </div>
        </div>

        <div class="search-container">
            <div class="search-wrapper">
                <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <path d="m21 21-4.35-4.35"></path>
                </svg>
                <input type="text" class="search-box" id="searchInput" placeholder="Enter CVE ID (e.g., CVE-2024-1234)" autocomplete="off">
            </div>
            <button class="search-btn" id="searchBtn">Search</button>
        </div>

        <div class="results-info" id="resultsInfo"></div>

        <div class="results-container" id="resultsContainer"></div>

        <div class="pagination" id="pagination"></div>

        <div class="footer">
            <p>
                &copy; 2026 <a href="https://github.com/secnotes" target="_blank">Security Notes</a>
                <span class="separator">|</span>
                <a href="https://github.com/secnotes/searchpoc" target="_blank" class="github-link">
                    <svg class="github-icon" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                    </svg>
                    Star on GitHub
                </a>
            </p>
            <p>Generated on ''' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
        </div>
    </div>

    <script>
        const cveData = ''' + cve_json + ''';

        const searchInput = document.getElementById('searchInput');
        const searchBtn = document.getElementById('searchBtn');
        const resultsContainer = document.getElementById('resultsContainer');
        const resultsInfo = document.getElementById('resultsInfo');
        const paginationContainer = document.getElementById('pagination');
        const themeToggle = document.getElementById('themeToggle');
        const themeIcon = document.getElementById('themeIcon');
        const themeText = document.getElementById('themeText');

        // Pagination settings
        const ITEMS_PER_PAGE = 20;
        let currentResults = [];
        let currentPage = 1;

        // Sun icon SVG path
        const sunIcon = '<circle cx="12" cy="12" r="5"></circle><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"></path>';
        // Moon icon SVG path
        const moonIcon = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>';

        // Theme handling
        function setTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);

            if (theme === 'light') {
                themeIcon.innerHTML = moonIcon;
                themeText.textContent = 'Dark';
            } else {
                themeIcon.innerHTML = sunIcon;
                themeText.textContent = 'Light';
            }
        }

        // Load saved theme, or follow system preference
        const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        const savedTheme = localStorage.getItem('theme') || systemTheme;
        setTheme(savedTheme);

        // Toggle theme on button click
        themeToggle.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            setTheme(currentTheme === 'light' ? 'dark' : 'light');
        });

        function searchCVE(query) {
            query = query.trim().toUpperCase();

            if (!query) {
                resultsContainer.innerHTML = '';
                resultsInfo.textContent = '';
                paginationContainer.innerHTML = '';
                currentResults = [];
                return;
            }

            const results = [];

            for (const [cveId, pocs] of Object.entries(cveData)) {
                if (cveId.includes(query)) {
                    results.push({ cveId, pocs });
                }
            }

            // Sort by CVE ID (newer first)
            results.sort((a, b) => b.cveId.localeCompare(a.cveId));

            currentResults = results;
            currentPage = 1;
            displayResults();
            renderPagination();
        }

        function displayResults() {
            const results = currentResults;
            const query = searchInput.value.trim().toUpperCase();

            if (results.length === 0) {
                resultsContainer.innerHTML = `
                    <div class="no-results">
                        <h3>No results found</h3>
                        <p>No CVE found matching "${query}"</p>
                    </div>
                `;
                resultsInfo.textContent = '0 results';
                return;
            }

            const totalPages = Math.ceil(results.length / ITEMS_PER_PAGE);
            const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
            const endIndex = startIndex + ITEMS_PER_PAGE;
            const pageResults = results.slice(startIndex, endIndex);

            resultsInfo.textContent = results.length + ' result' + (results.length > 1 ? 's' : '') + ' found' +
                (totalPages > 1 ? ', showing page ' + currentPage + ' of ' + totalPages : '');

            let html = '';
            for (const result of pageResults) {
                const pocCount = result.pocs.length;
                html += `
                    <div class="result-card">
                        <div class="cve-id">
                            ${result.cveId}
                            <span class="tag">${pocCount} PoC${pocCount > 1 ? 's' : ''}</span>
                        </div>
                        <div class="poc-links">
                            ${result.pocs.map(poc => `
                                <a href="${poc}" target="_blank" rel="noopener noreferrer" class="poc-link">
                                    <span>${poc}</span>
                                </a>
                            `).join('')}
                        </div>
                    </div>
                `;
            }

            resultsContainer.innerHTML = html;
        }

        function renderPagination() {
            const totalResults = currentResults.length;
            if (totalResults <= ITEMS_PER_PAGE) {
                paginationContainer.innerHTML = '';
                return;
            }

            const totalPages = Math.ceil(totalResults / ITEMS_PER_PAGE);

            let html = '<button id="prevPage" ' + (currentPage === 1 ? 'disabled' : '') + '>Previous</button>';

            // Page numbers
            html += '<div class="page-numbers">';
            const maxVisible = 5;
            let startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
            let endPage = Math.min(totalPages, startPage + maxVisible - 1);

            if (endPage - startPage < maxVisible - 1) {
                startPage = Math.max(1, endPage - maxVisible + 1);
            }

            if (startPage > 1) {
                html += '<span class="page-num" data-page="1">1</span>';
                if (startPage > 2) {
                    html += '<span class="page-info">...</span>';
                }
            }

            for (let i = startPage; i <= endPage; i++) {
                html += '<span class="page-num' + (i === currentPage ? ' active' : '') + '" data-page="' + i + '">' + i + '</span>';
            }

            if (endPage < totalPages) {
                if (endPage < totalPages - 1) {
                    html += '<span class="page-info">...</span>';
                }
                html += '<span class="page-num" data-page="' + totalPages + '">' + totalPages + '</span>';
            }

            html += '</div>';

            html += '<button id="nextPage" ' + (currentPage === totalPages ? 'disabled' : '') + '>Next</button>';

            paginationContainer.innerHTML = html;

            // Add event listeners
            document.getElementById('prevPage').addEventListener('click', () => {
                if (currentPage > 1) {
                    currentPage--;
                    displayResults();
                    renderPagination();
                    window.scrollTo(0, 0);
                }
            });

            document.getElementById('nextPage').addEventListener('click', () => {
                if (currentPage < totalPages) {
                    currentPage++;
                    displayResults();
                    renderPagination();
                    window.scrollTo(0, 0);
                }
            });

            document.querySelectorAll('.page-num').forEach(btn => {
                btn.addEventListener('click', () => {
                    const page = parseInt(btn.dataset.page);
                    if (page !== currentPage) {
                        currentPage = page;
                        displayResults();
                        renderPagination();
                        window.scrollTo(0, 0);
                    }
                });
            });
        }

        // Search on button click
        searchBtn.addEventListener('click', () => {
            searchCVE(searchInput.value);
        });

        // Search on Enter key press
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                searchCVE(searchInput.value);
            }
        });

        // Focus search on page load
        searchInput.focus();
    </script>
</body>
</html>'''

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"HTML file generated: {output_path}")
    print(f"Total CVE entries: {total_cves}")
    print(f"Total PoC links: {total_pocs}")


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    print("Loading configuration...")
    config = load_config()

    print("Loading CVE data from sources...")
    cve_data = load_cve_data(config)

    print("Generating HTML search engine...")
    generate_html(cve_data)

    print("Done!")


if __name__ == "__main__":
    main()