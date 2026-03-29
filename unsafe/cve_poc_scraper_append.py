import requests
from bs4 import BeautifulSoup
import json
import os
import sys
import re
from urllib.parse import urljoin
from datetime import datetime

def scrape_cve_page(page_num):
    """
    从指定页面获取CVE和PoC信息
    """
    url = f"https://unsafe.sh/cve?page={page_num}"

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        cves = []

        # 查找包含CVE数据的表格行或列表项
        paper_links = soup.find_all('a', class_='paper_list')

        for link in paper_links:
            href = link.get('href')
            if href:
                # 提取GitHub仓库名称部分
                repo_name = href.split('/')[-1]  # 最后一部分通常是仓库名

                # 使用正则表达式提取CVE ID (支持各种长度的数字组合)
                cve_matches = re.findall(r'CVE-\d{4}-\d{4,10}', repo_name, re.IGNORECASE)

                if cve_matches:
                    # 取第一个匹配的CVE ID（如果有多个的话）
                    cve_id = cve_matches[0].upper()

                    # 完整的PoC链接
                    poc_url = href
                    if poc_url.startswith('/'):
                        poc_url = urljoin("https://unsafe.sh", poc_url)

                    cves.append({
                        "CVE": cve_id,
                        "PoC": poc_url
                    })

        return cves

    except requests.RequestException as e:
        print(f"Error requesting page {page_num}: {e}")
        return []


def load_existing_data(json_file):
    """
    加载现有的CVE数据
    """
    if not os.path.exists(json_file):
        print(f"File {json_file} does not exist. Starting with empty data.")
        return []

    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"Loaded {len(data)} existing CVE records from {json_file}")
        return data
    except Exception as e:
        print(f"Error loading existing data: {e}")
        return []


def save_updated_data(existing_data, new_data, json_file):
    """
    将新数据添加到现有数据的顶部并保存
    """
    # 创建现有PoC链接的集合以便快速查找
    existing_poc_urls = set(item["PoC"] for item in existing_data)

    # 过滤掉已存在的PoC链接
    filtered_new_data = []
    for item in new_data:
        if item["PoC"] not in existing_poc_urls:
            filtered_new_data.append(item)
            existing_poc_urls.add(item["PoC"])  # 添加到集合，避免在同一轮中重复

    # 将新数据放在前面，保持现有数据不变
    updated_data = filtered_new_data + existing_data

    # 创建目录（如果不存在）
    os.makedirs(os.path.dirname(json_file), exist_ok=True)

    # 写入更新后的数据
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(updated_data, f, indent=2, ensure_ascii=False)

    print(f"Added {len(filtered_new_data)} new CVE records to the top of {json_file}")
    print(f"Total records after update: {len(updated_data)}")

    return len(filtered_new_data)


def is_page_fully_duplicate(page_cves, existing_data):
    """
    检查页面上的所有CVE是否都已在现有数据中存在
    """
    if not page_cves:
        return True  # 空页面视为重复

    existing_poc_urls = set(item["PoC"] for item in existing_data)

    for cve in page_cves:
        if cve["PoC"] not in existing_poc_urls:
            return False  # 至少有一个新的CVE

    return True  # 所有CVE都已存在


def incremental_scrape(json_file, start_page=1):
    """
    增量爬取CVE信息
    """
    print(f"Loading existing CVE data from {json_file}...")
    existing_data = load_existing_data(json_file)

    consecutive_duplicate_pages = 0  # 连续重复页面计数器
    page_num = start_page
    total_new_records = 0

    print("Starting incremental scraping...")

    while True:
        print(f"\nScraping page {page_num}...")
        current_page_cves = scrape_cve_page(page_num)

        if not current_page_cves:
            print(f"Page {page_num} is empty.")
            consecutive_duplicate_pages += 1
        elif is_page_fully_duplicate(current_page_cves, existing_data):
            print(f"All CVEs on page {page_num} already exist in the dataset.")
            consecutive_duplicate_pages += 1
        else:
            print(f"Found {len(current_page_cves)} CVEs on page {page_num}, {len([cve for cve in current_page_cves if cve['PoC'] not in [item['PoC'] for item in existing_data]])} are new.")
            consecutive_duplicate_pages = 0  # 重置计数器

            # 保存新增数据
            new_records_added = save_updated_data(existing_data, current_page_cves, json_file)

            # 重新加载现有数据以获取最新版本
            existing_data = load_existing_data(json_file)

            total_new_records += new_records_added

        print(f"Consecutive duplicate/skippable pages: {consecutive_duplicate_pages}/3")

        # 检查停止条件
        if consecutive_duplicate_pages >= 3:
            print(f"\nStopping - {consecutive_duplicate_pages} consecutive pages had all CVEs already in the dataset.")
            break

        page_num += 1

        # 防止无限循环的安全检查
        if page_num > 10000:  # 设置最大页面限制
            print("Reached maximum page limit (10000), stopping.")
            break

    print(f"\nIncremental scraping completed!")
    print(f"Total new records added: {total_new_records}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python incremental_cve_scraper.py <existing_cve_json_file>")
        sys.exit(1)

    json_file = sys.argv[1]

    print(f"Starting incremental CVE scraping...")
    print(f"Existing data file: {json_file}")

    incremental_scrape(json_file)


if __name__ == "__main__":
    main()