import os
import sys
import ssl
import math
import time
import base64
import socket
import requests
import datetime
import tldextract
import pandas as pd
from selenium import webdriver
from urllib.parse import urlparse, urlunparse
from selenium.webdriver.chrome.options import Options

if getattr(sys, 'frozen', False):
    BASE_PATH = sys._MEIPASS
else:
    BASE_PATH = os.path.dirname(__file__)

def get_url_len(url):
    return len(url)

def count_digits(url):
    count = 0
    for i in url:
        if '0' <= i <= '9':
            count += 1
    return count

def count_url_depth(url):
    url1 = url.split("://")[-1]
    return url1.count('/')

def entropy(url):
    frequency = {}
    for char in url:
        if char in frequency:
            frequency[char] += 1
        else:
            frequency[char] = 1

    entropy = 0.0
    length = len(url)
    for count in frequency.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return round(entropy, 1)

def popularity_score(url):
    popular_tlds = ['.com', '.org', '.net', '.gov', '.edu', '.co', '.io', '.ca', '.uk', '.de', '.us']

    tld_score = 5 if any(url.endswith(tld) for tld in popular_tlds) else 2

    if len(url) < 20:
        length_score = 5
    elif len(url) < 30:
        length_score = 3
    else:
        length_score = 1

    subdomain_count = url.count('.') - 1
    subdomain_score = max(1, 5 - subdomain_count)

    score = tld_score + length_score + subdomain_score
    return score

def get_domain(url):
    if '://' in url:
        url = url.split('://')[1]
    if url.startswith('www.'):
        url = url[4:]
    domain = url.split('/')[0].split(':')[0] 
    return domain

def count_subdomain(url):
    if '://' in url:
        url = url.split('://')[1]
    domain_part = url.split('/')[0]
    parts = domain_part.split('.')
    if len(parts) < 2:
        return 0
    return len(parts) - 2

def calculate_entropy(url):
    domain = get_domain(url)
    frequency = {}
    for char in domain:
        if char in frequency:
            frequency[char] += 1
        else:
            frequency[char] = 1

    total_chars = len(domain)

    entropy = 0.0
    for count in frequency.values():
        probability = count / total_chars
        entropy -= probability * (0 if probability == 0 else math.log2(probability))

    return round(entropy, 1)

def path_length(url):
    path_start = url.find('/', url.find('//') + 2)

    if path_start == -1:
        return 0

    path_end = url.find('?') if '?' in url else len(url)
    path = url[path_start:path_end]

    return len(path)

def count_special_char(url):
    special_char = ['-', '_', '.', '=', '?', '&', '@', '#', '%', ':', '~']
    return sum(url.count(char) for char in special_char)

def has_https(url):
    if url.startswith('https://'):
        return 1
    else:
        return 0

def has_ip(url):
    main_part = url.split('/')[2] if '//' in url else url.split('/')[0]
    parts = main_part.split('.')

    if len(parts) == 4:
        for part in parts:
            if not part.isdigit() or not (0 <= int(part) <= 255):
                return 0
        return 1
    return 0

def has_suspicious_keywords(url, is_registered):
    suspicious_keywords = [
        'login', 'signin', 'account', 'verify', 'update', 'secure', 'bank',
        'password', 'confirm', 'billing', 'payment', 'invoice', 'card',
        'pin', 'ssn', 'security', 'credential', 'checkout', 'wallet'
    ]

    url_lower = url.lower()
    match_count = sum(1 for keyword in suspicious_keywords if keyword in url_lower)

    if match_count >= 3:
        return 1 
    elif match_count == 2 and not is_registered:
        return 1 
    elif match_count == 1 and not is_registered:
        return 1
    else:
        return 0

def get_tld(url):
    if '://' in url:
        url = url.split('://')[1]
    if url.startswith('www.'):
        url = url[4:]
    domain_part = url.split('/')[0].split(':')[0] 
    parts = domain_part.split(".")
    return parts[-1] if len(parts) > 1 else None

suspicious_tlds_df = pd.read_csv(os.path.join(BASE_PATH, "Datasets", "suspicious_tlds_list.csv"))
suspicious_tlds = set(suspicious_tlds_df['metadata_tld'].dropna().str.lower())

def has_suspicious_tld(url):
    tld = get_tld(url)
    if tld is None:
        return 0 
    return 1 if tld.lower() in suspicious_tlds else 0

usecols = ['website'] 

df_companies1 = pd.read_csv(os.path.join(BASE_PATH, "Datasets", "companies-2023-q4-sm.csv"), usecols=usecols)
df_companies2 = pd.read_csv(os.path.join(BASE_PATH, "Datasets", "free_company_dataset.csv"), usecols=usecols)

domains_1 = df_companies1['website'].dropna().str.lower().str.strip() \
    .str.replace('http://', '', regex=False) \
    .str.replace('https://', '', regex=False) \
    .str.replace('www.', '', regex=False) \
    .str.extract(r'^([a-z0-9.-]+)')[0]

domains_2 = df_companies2['website'].dropna().str.lower().str.strip() \
    .str.replace('http://', '', regex=False) \
    .str.replace('https://', '', regex=False) \
    .str.replace('www.', '', regex=False) \
    .str.extract(r'^([a-z0-9.-]+)')[0]

registered_domains = set(domains_1.dropna()) | set(domains_2.dropna())

def is_registered_company_domain(url):
    try:
        ext = tldextract.extract(url)
        registered_domain = f"{ext.domain}.{ext.suffix}".lower() 
        return 1 if registered_domain in registered_domains else 0
    except:
        return 0
    

def resolve_final_url(url):
    try:
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument("--window-size=1280,800")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)

        options.add_experimental_option("prefs", {
            "download.prompt_for_download": False,
            "profile.default_content_settings.popups": 0,
            "download.default_directory": "/dev/null"
        })

        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(8)
        print(f"🌐 Navigating to: {url}")
        driver.get(url)
        time.sleep(2)
        resolved = driver.current_url
        print(f"Resolved to: {driver.current_url}")
        driver.quit()

        parsed = urlparse(resolved)
        netloc = parsed.hostname or ''
        cleaned_url = urlunparse((parsed.scheme, netloc, parsed.path or '', '', '', ''))
        return cleaned_url

    except Exception as e:
        print(f"[!] Error in resolve_final_url: {e}")
        return url

def truncate_url_path(url, max_segments=2, max_path_length=30):
    try:
        parsed = urlparse(url)
        path_segments = parsed.path.strip('/').split('/')

        truncated_segments = path_segments[:max_segments]

        truncated_segments = [
            seg if len(seg) <= max_path_length else seg[:max_path_length]
            for seg in truncated_segments
        ]

        truncated_path = '/' + '/'.join(truncated_segments)
        return urlunparse((parsed.scheme, parsed.netloc, truncated_path, '', '', ''))

    except Exception:
        return url
    
def get_screenshot_base64(url):
    try:
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument("--window-size=1280,800")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)

        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(10)
        driver.get(url)
        time.sleep(2)

        screenshot = driver.get_screenshot_as_base64()
        driver.quit()
        return screenshot

    except Exception as e:
        print(f"[!] Screenshot error: {e}")
        return None

def get_url_metadata(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        ip = socket.gethostbyname(hostname)

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(3)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        ssl_info = {
            "IP Address": ip,
            "SSL Issuer": cert.get('issuer')[0][0][1],
            "Valid From": cert.get('notBefore'),
            "Valid To": cert.get('notAfter'),
        }
        return ssl_info
    except Exception as e:
        return {"IP Address": "Unavailable", "SSL Info": "Unavailable"}

def extract_features(url):
    original_url = url.strip().rstrip('/')
    resolved_url = resolve_final_url(original_url)

    def clean_url(u):
        u = u.strip().rstrip('/')
        return u.replace("://www.", "://").replace("www.", "")

    original_url = clean_url(original_url)
    resolved_url = clean_url(resolved_url)

    original_domain = get_domain(original_url)
    resolved_domain = get_domain(resolved_url)

    def extract_all_features(u):
        reg = is_registered_company_domain(u)
        keyword_flag = has_suspicious_keywords(u, reg)
        if reg == 1 and keyword_flag == 0:
            u = truncate_url_path(u)
        features = {
            'URL Length': get_url_len(u),
            'Digits': count_digits(u),
            'URL Depth': count_url_depth(u),
            'URL Entropy': entropy(u),
            'URL Popularity Score': popularity_score(u),
            'URL Domain': get_domain(u),
            'Sub-Domain': count_subdomain(u),
            'Domain Entropy': calculate_entropy(u),
            'Is Registered Company Domain': reg,
            'Path Length': path_length(u),
            'Special Characters': count_special_char(u),
            'Has HTTPS': has_https(u),
            'Has IP': has_ip(u),
            'Has Suspicious Keywords': keyword_flag,
            'TLD': get_tld(u),
            'Has Suspicious TLD': has_suspicious_tld(u)
        }
        features.update(get_url_metadata(u))
        return features, u

    original_features, final_original = extract_all_features(original_url)
    resolved_features, final_resolved = extract_all_features(resolved_url)

    return {
        "original_url": original_url,
        "resolved_url": resolved_url,
        "final_url": final_resolved,
        "original_features": original_features,
        "resolved_features": resolved_features,
        "redirection_mismatch": original_domain != resolved_domain,
        "original_domain": original_domain,
        "resolved_domain": resolved_domain
    }