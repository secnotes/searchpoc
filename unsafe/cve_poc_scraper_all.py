import requests
from bs4 import BeautifulSoup
import json
import os
import time
from urllib.parse import urljoin
import re
from datetime import datetime
import sys

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
        # 根据观察到的HTML结构，CVE信息在class为'paper_list'的链接中
        paper_links = soup.find_all('a', class_='paper_list')

        for link in paper_links:
            href = link.get('href')
            if href:
                # 提取GitHub仓库名称部分
                repo_name = href.split('/')[-1]  # 最后一部分通常是仓库名

                # 使用正则表达式提取CVE ID (支持各种长度的数字组合)
                # CVE标准格式是 CVE-YYYY-NNNN 或 CVE-YYYY-NNNNN 等
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


def save_to_json(data, filename="output/cve_poc_all.json"):
    """
    将数据保存到JSON文件
    """
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] Saved {len(data)} records to {filename}")


def scrape_range_of_pages(output_file, start_page=1, end_page=2000):
    """
    爬取指定范围内的页面
    """
    all_cves = []  # 存储所有爬取到的数据
    consecutive_empty_pages = 0  # 连续空页计数器

    for page_num in range(start_page, end_page + 1):
        cves = scrape_cve_page(page_num)

        # 检查是否页面为空或者没有获取到任何数据，表示可能已到达末尾
        if not cves:
            consecutive_empty_pages += 1
            print(f"Page {page_num} - Empty (Empty count: {consecutive_empty_pages})")

            # 如果连续遇到多个空页面，可能表示已经到达末尾
            if consecutive_empty_pages >= 3:  # 连续3个空页则停止
                print(f"Stopped - {consecutive_empty_pages} consecutive empty pages.")
                break
        else:
            consecutive_empty_pages = 0  # 重置连续空页计数器

            # 将当前页面所有数据添加到总列表中
            all_cves.extend(cves)

            # 对当前页面的数据进行初步分析以显示统计信息
            # 创建一个临时的总体去重列表来计算统计信息
            all_poc_urls = [cve["PoC"] for cve in all_cves]
            all_unique_pocs = set(all_poc_urls)

            # 统计当前页面的新数据量（去重后）
            old_poc_urls = [cve["PoC"] for cve in all_cves[:-len(cves)]]
            old_unique_pocs = set(old_poc_urls)

            new_unique_count = len(all_unique_pocs) - len(old_unique_pocs)

            original_count = len(cves)
            skipped_count = original_count - new_unique_count

            if new_unique_count > 0:
                print(f"[+] Page {page_num} - New: {new_unique_count}")

        # 每10页保存一次（在第10、20、30...页时保存）
        if page_num % 10 == 0:
            # 在保存前进行去重
            deduplicated_cves = []
            saved_pocs = set()

            for cve in all_cves:
                poc_url = cve["PoC"]
                if poc_url not in saved_pocs:
                    deduplicated_cves.append(cve)
                    saved_pocs.add(poc_url)

            save_to_json(deduplicated_cves, output_file)

    # 最后保存完整数据
    if all_cves:
        # 在最终保存时进行去重
        deduplicated_cves = []
        saved_pocs = set()

        for cve in all_cves:
            poc_url = cve["PoC"]
            if poc_url not in saved_pocs:
                deduplicated_cves.append(cve)
                saved_pocs.add(poc_url)

        # 使用专门的保存函数，会自动带时间戳
        save_to_json(deduplicated_cves, output_file)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Completed - Total: {len(deduplicated_cves)} unique CVE-PoC records")

        # 显示统计信息
        cve_count = len(deduplicated_cves)
        unique_cves = set(item["CVE"] for item in deduplicated_cves)
        unique_cve_count = len(unique_cves)

        print(f"Total records: {cve_count}")
        print(f"Unique CVEs: {unique_cve_count}")

        if deduplicated_cves:
            print("\nFirst 5 records preview:")
            for i, record in enumerate(deduplicated_cves[:5]):
                print(f"  {i+1}. {record}")

    return all_cves


if __name__ == "__main__":
    # 检查命令行参数
    if len(sys.argv) < 2:
        print("Usage: python script.py <output_file>")
        sys.exit(1)

    output_file = sys.argv[1]

    print("Starting to scrape CVE and PoC info...")

    # 爬取多页数据
    cve_data = scrape_range_of_pages(output_file, start_page=1, end_page=2000)

    print(f"Collected {len(cve_data)} unique CVE-PoC records")