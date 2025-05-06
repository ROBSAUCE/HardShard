#!/usr/bin/env python3
import argparse
import requests
import sys
import json
from datetime import datetime
import readline
from colorama import init, Fore, Style
import re

init(autoreset=True)

# Disable SSL warnings for self-signed certs (common in misconfigurations)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def log(msg, verbose, silent):
    if not silent and verbose:
        print(msg)

def get_indices(base_url, verbose, silent):
    """Enumerate open indices on the Elasticsearch instance."""
    url = f"{base_url}/_cat/indices?format=json"
    try:
        resp = requests.get(url, verify=False, timeout=5)
        if resp.status_code == 200:
            indices = resp.json()
            log(f"[+] Found {len(indices)} indices", verbose, silent)
            return indices
        elif resp.status_code == 401:
            log("[!] Authentication required (401 Unauthorized)", verbose, silent)
        elif resp.status_code == 403:
            log("[!] Access forbidden (403 Forbidden)", verbose, silent)
        else:
            log(f"[!] Unexpected status code: {resp.status_code}", verbose, silent)
    except requests.exceptions.RequestException as e:
        log(f"[!] Connection error: {e}", verbose, silent)
    return []

def search_index(base_url, index, keyword=None, date=None, verbose=False, silent=False):
    """Search an index with optional keyword and date filter."""
    url = f"{base_url}/{index}/_search"
    query = {"query": {"match_all": {}}}
    if keyword:
        query = {"query": {"query_string": {"query": keyword}}}
    if date:
        # Try to filter by @timestamp or timestamp field
        query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": date
                    }
                }
            }
        }
    try:
        resp = requests.get(url, json=query, verify=False, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 401:
            log("[!] Authentication required (401 Unauthorized)", verbose, silent)
        elif resp.status_code == 403:
            log("[!] Access forbidden (403 Forbidden)", verbose, silent)
        else:
            log(f"[!] Unexpected status code: {resp.status_code}", verbose, silent)
    except requests.exceptions.RequestException as e:
        log(f"[!] Connection error: {e}", verbose, silent)
    return None

def luhn_checksum(card_number):
    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    return (sum(odd_digits) + sum(sum(digits_of(d*2)) for d in even_digits)) % 10

def is_luhn_valid(card_number):
    card_number = re.sub(r"\D", "", card_number)
    if len(card_number) < 12 or len(card_number) > 19:
        return False
    try:
        return luhn_checksum(card_number) == 0
    except Exception:
        return False

def scan_for_secrets(doc):
    findings = []
    text = json.dumps(doc)
    # Credit card regex (Luhn validated)
    cc_matches = re.findall(r"(?:\d[ -]*?){13,19}", text)
    for cc in cc_matches:
        if is_luhn_valid(cc):
            findings.append(("Credit Card", cc.strip()))
    # SSN
    for ssn in re.findall(r"\b\d{3}-\d{2}-\d{4}\b", text):
        findings.append(("SSN", ssn))
    # Email
    for email in re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text):
        findings.append(("Email", email))
    # AWS key
    for ak in re.findall(r"AKIA[0-9A-Z]{16}", text):
        findings.append(("AWS Access Key", ak))
    # JWT
    for jwt in re.findall(r"eyJ[0-9a-zA-Z_-]{10,}\.[0-9a-zA-Z_-]{10,}\.[0-9a-zA-Z_-]{10,}", text):
        findings.append(("JWT", jwt))
    # Password fields
    for k, v in doc.items():
        if isinstance(v, str) and re.search(r"pass(word)?|pwd|secret|token|key", k, re.I):
            findings.append((f"Field:{k}", v))
    # Generic API keys
    for apikey in re.findall(r"(?i)(?:api|secret|token|key)[\s:=\"]*([0-9a-zA-Z\-_]{16,})", text):
        findings.append(("API Key/Token", apikey))
    return findings

def interactive_shell(base_url, verbose, silent):
    """Interactive shell for Elasticsearch navigation."""
    current_index = None
    indices_cache = []
    prompt_base = Fore.GREEN + "hardshard" + Style.RESET_ALL
    while True:
        prompt = f"{prompt_base}:{Fore.YELLOW}{current_index if current_index else '/'}{Style.RESET_ALL}$ "
        try:
            cmd = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break
        if not cmd:
            continue
        parts = cmd.split()
        if parts[0] in ("exit", "quit"):
            print("Bye!")
            break
        elif parts[0] == "ls":
            if not indices_cache:
                indices_cache = get_indices(base_url, verbose, silent)
            if current_index:
                # List docs in current index (show _id and maybe a preview)
                url = f"{base_url}/{current_index}/_search"
                query = {"query": {"match_all": {}}, "size": 10}
                try:
                    resp = requests.get(url, json=query, verify=False, timeout=10)
                    if resp.status_code == 200:
                        hits = resp.json().get('hits', {}).get('hits', [])
                        print(Fore.CYAN + f"[Docs in {current_index}]:" + Style.RESET_ALL)
                        for hit in hits:
                            doc_id = hit.get('_id')
                            preview = str(hit.get('_source'))[:60].replace('\n', ' ')
                            print(f"  {Fore.YELLOW}{doc_id}{Style.RESET_ALL} | {preview}")
                        if not hits:
                            print(Fore.YELLOW + "[No documents found in this index]" + Style.RESET_ALL)
                    else:
                        print(Fore.RED + f"Error listing docs: {resp.status_code}" + Style.RESET_ALL)
                except requests.exceptions.RequestException as e:
                    print(Fore.RED + f"Connection error: {e}" + Style.RESET_ALL)
            else:
                print(Fore.CYAN + "[Indices]" + Style.RESET_ALL)
                for idx in indices_cache:
                    print(f"  {Fore.YELLOW}{idx.get('index')}{Style.RESET_ALL} | Docs: {idx.get('docs.count')} | Status: {idx.get('status')}")
        elif parts[0] == "ls_nonempty":
            if not indices_cache:
                indices_cache = get_indices(base_url, verbose, silent)
            if current_index:
                print(Fore.YELLOW + "[!] ls_nonempty only works at root (indices view). Use 'cd ..' first." + Style.RESET_ALL)
                continue
            print(Fore.CYAN + "[Non-empty Indices]" + Style.RESET_ALL)
            found = False
            for idx in indices_cache:
                try:
                    count = int(idx.get('docs.count', '0'))
                except (TypeError, ValueError):
                    count = 0
                if count > 0:
                    found = True
                    print(f"  {Fore.YELLOW}{idx.get('index')}{Style.RESET_ALL} | Docs: {count} | Status: {idx.get('status')}")
            if not found:
                print(Fore.YELLOW + "[No non-empty indices found]" + Style.RESET_ALL)
        elif parts[0] == "cd":
            if len(parts) < 2:
                print(Fore.RED + "Usage: cd <index> or cd .." + Style.RESET_ALL)
                continue
            target = parts[1]
            if target == "..":
                current_index = None
                print("Returned to root (indices view)")
                continue
            if not indices_cache:
                indices_cache = get_indices(base_url, verbose, silent)
            found = any(idx.get('index') == target for idx in indices_cache)
            if found:
                current_index = target
                print(f"Now in index: {Fore.YELLOW}{current_index}{Style.RESET_ALL}")
            else:
                print(Fore.RED + f"Index '{target}' not found. Staying in {current_index if current_index else 'root'}." + Style.RESET_ALL)
        elif parts[0] == "search":
            if not current_index:
                print(Fore.RED + "No index selected. Use 'cd <index>' first." + Style.RESET_ALL)
                continue
            keyword = " ".join(parts[1:]) if len(parts) > 1 else None
            result = search_index(base_url, current_index, keyword, None, verbose, silent)
            if result:
                hits = result.get('hits', {}).get('hits', [])
                print(Fore.CYAN + f"[+] Found {len(hits)} results:" + Style.RESET_ALL)
                for hit in hits:
                    print(json.dumps(hit.get('_source', {}), indent=2))
            else:
                print(Fore.RED + "No results or error." + Style.RESET_ALL)
        elif parts[0] == "cat":
            if not current_index:
                print(Fore.RED + "No index selected. Use 'cd <index>' first." + Style.RESET_ALL)
                continue
            if len(parts) < 2:
                print(Fore.RED + "Usage: cat <doc_id>" + Style.RESET_ALL)
                continue
            doc_id = parts[1]
            # Try _doc endpoint first
            url = f"{base_url}/{current_index}/_doc/{doc_id}"
            try:
                resp = requests.get(url, verify=False, timeout=5)
                if resp.status_code == 200:
                    doc = resp.json()
                    print(json.dumps(doc.get('_source', {}), indent=2))
                elif resp.status_code == 404:
                    # Try fallback to _all for older ES
                    url_fallback = f"{base_url}/{current_index}/_all/{doc_id}"
                    resp2 = requests.get(url_fallback, verify=False, timeout=5)
                    if resp2.status_code == 200:
                        doc = resp2.json()
                        print(json.dumps(doc.get('_source', {}), indent=2))
                    else:
                        print(Fore.RED + f"Document '{doc_id}' not found. Possible reasons: deleted, permissions, or ES version/type mismatch." + Style.RESET_ALL)
                        if verbose:
                            print(Fore.YELLOW + f"Tried: {url} and {url_fallback}" + Style.RESET_ALL)
                else:
                    print(Fore.RED + f"Error: {resp.status_code}" + Style.RESET_ALL)
                    if verbose:
                        print(Fore.YELLOW + f"Request: {url}" + Style.RESET_ALL)
            except requests.exceptions.RequestException as e:
                print(Fore.RED + f"Connection error: {e}" + Style.RESET_ALL)
        elif parts[0] == "pwd":
            print(f"Current index: {Fore.YELLOW}{current_index if current_index else '/'}{Style.RESET_ALL}")
        elif parts[0] == "help":
            print(Fore.CYAN + "Commands:" + Style.RESET_ALL)
            print("  ls                 - List indices (or docs in current index)")
            print("  ls_nonempty        - List only non-empty indices")
            print("  cd <index>         - Change to index (like directory)")
            print("  cd ..              - Return to indices view (root)")
            print("  search <keyword>   - Search in current index")
            print("  cat <doc_id>       - View document by ID in current index")
            print("  secretscan [N|all] - Scan N or all docs in current index for secrets (default 100)")
            print("  pwd                - Show current index")
            print("  help               - Show this help")
            print("  exit/quit          - Exit shell")
        elif parts[0] == "secretscan":
            if not current_index:
                print(Fore.RED + "No index selected. Use 'cd <index>' first." + Style.RESET_ALL)
                continue
            # Parse argument: secretscan [N|all]
            scan_limit = 100
            scan_all = False
            if len(parts) > 1:
                if parts[1].lower() == "all":
                    scan_all = True
                else:
                    try:
                        scan_limit = int(parts[1])
                        if scan_limit < 1:
                            raise ValueError
                    except ValueError:
                        print(Fore.RED + "Usage: secretscan [N|all] (N must be positive integer or 'all')" + Style.RESET_ALL)
                        continue
            if scan_all:
                print(Fore.CYAN + f"[!] Scanning ALL docs in {current_index} for secrets (this may take a while)..." + Style.RESET_ALL)
                url = f"{base_url}/{current_index}/_search"
                size = 500
                total_findings = 0
                from_ = 0
                total_docs = None
                while True:
                    query = {"query": {"match_all": {}}, "size": size, "from": from_}
                    try:
                        resp = requests.get(url, json=query, verify=False, timeout=30)
                        if resp.status_code == 200:
                            data = resp.json()
                            # Handle ES hits.total as int or dict
                            total_raw = data.get('hits', {}).get('total', 0)
                            if isinstance(total_raw, dict):
                                total_docs = total_raw.get('value', 0)
                            else:
                                total_docs = total_raw
                            hits = data.get('hits', {}).get('hits', [])
                            if not hits:
                                break
                            for hit in hits:
                                doc_id = hit.get('_id')
                                doc = hit.get('_source', {})
                                findings = scan_for_secrets(doc)
                                if findings:
                                    total_findings += len(findings)
                                    print(Fore.YELLOW + f"Doc {doc_id}:" + Style.RESET_ALL)
                                    for typ, val in findings:
                                        print(f"  {Fore.RED}{typ}{Style.RESET_ALL}: {val}")
                            from_ += size
                            if from_ >= total_docs:
                                break
                        else:
                            print(Fore.RED + f"Error searching docs: {resp.status_code}" + Style.RESET_ALL)
                            break
                    except requests.exceptions.RequestException as e:
                        print(Fore.RED + f"Connection error: {e}" + Style.RESET_ALL)
                        break
                if total_findings == 0:
                    print(Fore.GREEN + "No secrets found in all docs." + Style.RESET_ALL)
                else:
                    print(Fore.RED + f"[!] {total_findings} secrets found!" + Style.RESET_ALL)
            else:
                print(Fore.CYAN + f"[!] Scanning first {scan_limit} docs in {current_index} for secrets..." + Style.RESET_ALL)
                url = f"{base_url}/{current_index}/_search"
                query = {"query": {"match_all": {}}, "size": scan_limit}
                try:
                    resp = requests.get(url, json=query, verify=False, timeout=20)
                    if resp.status_code == 200:
                        hits = resp.json().get('hits', {}).get('hits', [])
                        total_findings = 0
                        for hit in hits:
                            doc_id = hit.get('_id')
                            doc = hit.get('_source', {})
                            findings = scan_for_secrets(doc)
                            if findings:
                                total_findings += len(findings)
                                print(Fore.YELLOW + f"Doc {doc_id}:" + Style.RESET_ALL)
                                for typ, val in findings:
                                    print(f"  {Fore.RED}{typ}{Style.RESET_ALL}: {val}")
                        if total_findings == 0:
                            print(Fore.GREEN + f"No secrets found in first {scan_limit} docs." + Style.RESET_ALL)
                        else:
                            print(Fore.RED + f"[!] {total_findings} secrets found!" + Style.RESET_ALL)
                    else:
                        print(Fore.RED + f"Error searching docs: {resp.status_code}" + Style.RESET_ALL)
                except requests.exceptions.RequestException as e:
                    print(Fore.RED + f"Connection error: {e}" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"Unknown command: {cmd}" + Style.RESET_ALL)

def print_ascii_art():
    art = r"""

|| _   _               _ ____  _                   _ ||
||| | | | __ _ _ __ __| / ___|| |__   __ _ _ __ __| |||
||| |_| |/ _` | '__/ _` \\___ \| '_ \ / _` | '__/ _` |||
|||  _  | (_| | | | (_| |___) | | | | (_| | | | (_| |||
|||_| |_|\__,_|_|  \__,_|____/|_| |_|\__,_|_|  \__,_|||
    """
    print(art)

def main():
    parser = argparse.ArgumentParser(description="Hardshard - elasticsearch shell")
    parser.add_argument("--host", required=True, help="Target Elasticsearch host (IP or domain)")
    parser.add_argument("--port", default=9200, type=int, help="Elasticsearch port (default: 9200)")
    parser.add_argument("--https", action="store_true", help="Use HTTPS (default: HTTP)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--silent", action="store_true", help="Silent mode (minimal output)")
    args = parser.parse_args()

    proto = "https" if args.https else "http"
    base_url = f"{proto}://{args.host}:{args.port}"

    print_ascii_art()

    # Check connection before proceeding
    try:
        resp = requests.get(f"{base_url}/_cat/health", verify=False, timeout=8)
        if resp.status_code == 200:
            print(Fore.GREEN + f"[+] Connected to Elasticsearch at {base_url}" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"[!] Unable to connect to Elasticsearch at {base_url} (status {resp.status_code})" + Style.RESET_ALL)
            sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[!] Connection error: {e}" + Style.RESET_ALL)
        sys.exit(1)

    print(Fore.YELLOW + "Type 'help' for commands." + Style.RESET_ALL)
    interactive_shell(base_url, args.verbose, args.silent)

if __name__ == "__main__":
    main()
