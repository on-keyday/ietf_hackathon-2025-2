#!/usr/bin/env python3
import os
import sys
import re
import requests
import time
import random
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

# クローラーを識別する User-Agent を指定（必要に応じて変更）
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BestEffortCrawler/1.0; +https://example.com/crawler)"
}

# サーバー負荷軽減のための基本リクエスト間隔（秒）
DEFAULT_CRAWL_DELAY = 1.0

def canonicalize_url(url):
    """
    URL の正規化を行い、フラグメント（#以降）の部分を除去して返します。
    これにより、フラグメントのみが異なる URL を同一と判断できます。
    """
    parsed = urlparse(url)
    # fragment部分を空文字に置換してから URL を生成
    canonical = parsed._replace(fragment="").geturl()
    return canonical

def can_fetch(url, user_agent=HEADERS["User-Agent"]):
    """
    robots.txt を読み込み、指定 URL のクロールが許可されているかチェックします。
    robots.txt の取得に失敗した場合は許可するものとします。
    """
    parsed = urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp = RobotFileParser()
    rp.set_url(robots_url)
    try:
        rp.read()
        return rp.can_fetch(user_agent, url)
    except Exception as e:
        print(f"[Warning] robots.txt の読み込みに失敗しました ({robots_url}): {e}")
        return True

def is_valid_url(url):
    """
    URL のスキームが http または https であるかチェックします。
    """
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https")

def sanitize_segment(segment):
    """
    パスの各セグメント内で、OS で使えない文字をアンダースコアに置換します。
    """
    return re.sub(r'[<>:"/\\|?*]', '_', segment)

def get_output_filepath(url, output_dir):
    """
    URL のドメインおよびパスに合わせたディレクトリ構造を作成し、
    保存先ファイルパス（ディレクトリも含む）を返します。

    例）
      URL: http://example.com/some/path/page.html
      → 出力パス: <output_dir>/example.com/some/path/page.html

      URL がルートの場合、またはパスが末尾で終わる場合は "index.html" として保存します。
    """
    parsed = urlparse(url)
    # ドメイン部分をサニタイズ
    domain = sanitize_segment(parsed.netloc)
    path = parsed.path
    # "/" で分割して各セグメントをサニタイズ（空文字は除外）
    segments = [sanitize_segment(segment) for segment in path.split("/") if segment]
    if not segments:
        # URL がドメイン直下の場合 → index.html とする
        file_name = "index.html"
        dir_path = os.path.join(output_dir, domain)
    else:
        last_segment = segments[-1]
        if '.' in last_segment:
            # 最後のセグメントにドットが含まれているならファイル名とみなす
            file_name = last_segment
            dir_path = os.path.join(output_dir, domain, *segments[:-1])
        else:
            # 末尾がディレクトリの場合 → index.html とする
            file_name = "index.html"
            dir_path = os.path.join(output_dir, domain, *segments)
    return os.path.join(dir_path, file_name)

def save_content(url, content, output_dir):
    """
    取得したコンテンツを、URL に対応するディレクトリ構造で output_dir 内に保存します。
    """
    filepath = get_output_filepath(url, output_dir)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    try:
        with open(filepath, "wb") as f:
            f.write(content)
        print(f"[Saved] {url} -> {filepath}")
    except Exception as e:
        print(f"[Error] {url} の保存に失敗: {e}")

def fetch_url(url, delay=DEFAULT_CRAWL_DELAY):
    """
    指定 URL のコンテンツを取得します。
    サーバー負荷軽減のため、リクエスト前にランダムなディレイを挿入します。
    """
    # delay ～ (delay+0.5) 秒の間、待機
    time.sleep(random.uniform(delay, delay + 0.5))
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        return response.content, response.text
    except Exception as e:
        print(f"[Error] {url} の取得に失敗: {e}")
        return None, None

def parse_references(html, base_url):
    """
    HTML 内の <a> タグからリンクを抽出し、絶対 URL に変換してリストで返します。
    """
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"]
        abs_url = urljoin(base_url, href)
        if is_valid_url(abs_url):
            links.add(abs_url)
    return list(links)

def build_tree(url, output_dir, visited, depth, max_depth, delay=DEFAULT_CRAWL_DELAY):
    """
    指定 URL から再帰的にリンクをたどり、ツリー構造（辞書型）を構築します。

    Args:
      - url: 現在処理中の URL
      - output_dir: コンテンツの保存先ディレクトリ
      - visited: 既に処理済みの URL を保持する集合（無限ループ防止用）
      - depth: 残り再帰深度
      - max_depth: 最大再帰深度（表示用インデントに利用）
      - delay: 各リクエスト前に挿入する待機時間

    Returns:
      ツリーノード（例: {"url": <url>, "children": [子ノード, …]}）
    """
    # URL を正規化（fragment部分を除去）
    canonical_url = canonicalize_url(url)
    if canonical_url in visited:
        return None
    visited.add(canonical_url)

    # robots.txt によりクロールが禁止されているか確認
    if not can_fetch(url):
        print(f"[Skipping] {url} は robots.txt によりクロール禁止です")
        return None

    indent = " " * ((max_depth - depth) * 2)
    print(f"{indent}[Fetching] {url}")

    content_bytes, content_text = fetch_url(url, delay)
    if content_bytes is None:
        return None

    # 取得したコンテンツを保存
    save_content(url, content_bytes, output_dir)

    node = {"url": url, "children": []}
    if depth <= 0:
        return node

    # HTML コンテンツの場合のみリンクを抽出
    if content_text is not None and "<html" in content_text.lower():
        refs = parse_references(content_text, url)
        for ref in refs:
            child_node = build_tree(ref, output_dir, visited, depth - 1, max_depth, delay)
            if child_node:
                node["children"].append(child_node)
    return node

def print_tree(node, indent=0):
    """
    ツリー構造をインデント付きで標準出力に表示します。
    """
    if node is None:
        return
    print(" " * indent + node["url"])
    for child in node.get("children", []):
        print_tree(child, indent + 2)

def main():
    if len(sys.argv) < 3:
        print("Usage: python script.py <starting_url> <output_directory> [max_depth] [crawl_delay]")
        sys.exit(1)
    starting_url = sys.argv[1]
    output_dir = sys.argv[2]
    max_depth = 2
    if len(sys.argv) >= 4:
        try:
            max_depth = int(sys.argv[3])
        except ValueError:
            print("max_depth は整数で指定してください")
            sys.exit(1)
    delay = DEFAULT_CRAWL_DELAY
    if len(sys.argv) >= 5:
        try:
            delay = float(sys.argv[4])
        except ValueError:
            print("crawl_delay は数値で指定してください")
            sys.exit(1)
    visited = set()
    tree = build_tree(starting_url, output_dir, visited, max_depth, max_depth, delay)
    print("\nReference Tree:")
    print_tree(tree)
    # ツリー構造をファイルに保存
    with open(os.path.join(output_dir, "tree.txt"), "w") as f:
        sys.stdout = f
        print_tree(tree)
        sys.stdout = sys.__stdout__

if __name__ == "__main__":
    main()
