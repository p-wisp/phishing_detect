import json
import math
import re
import ipaddress
import os
import sys
import csv
from collections import Counter
from urllib.parse import urlparse

import tldextract
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

# get_urlscan.py 파일에서 함수 임포트
from get_urlscan import get_json, get_dom




def load_whitelist(filepath):
    whitelist_set = set()
    if not os.path.exists(filepath):
        print(f"화이트리스트 파일'{filepath}'없음 = 경로오류.")
        return whitelist_set
    
    try:
        with open(filepath, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            try:
                first_row = next(reader)
                if 'domain' not in first_row[0].lower():
                    domain_to_add = tldextract.extract(first_row[0].strip()).top_domain_under_public_suffix
                    if domain_to_add:
                        whitelist_set.add(domain_to_add)
            except StopIteration:
                return whitelist_set 
                
            for row in reader:
                if row:
                    domain = row[0].strip()
                    if domain:
                        registered_domain = tldextract.extract(domain).top_domain_under_public_suffix
                        if registered_domain:
                            whitelist_set.add(registered_domain)
    except Exception as e:
        print(f"화이트리스트 파일 '{filepath}' 로드 중 오류: {e}")
    
    print(f"'{filepath}'에서 {len(whitelist_set)}개의 화이트리스트 도메인 로드.")
    return whitelist_set


def calculate_entropy(s):#엔트로피 구하는 식
    if not s:
        return 0.0
    p, lns = Counter(s), float(len(s))
    return -sum(count/lns * math.log2(count/lns) for count in p.values())


def get_hostname(url):
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
             url = "http://" + url
             parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None

def levenshtein_similarity(s1, s2):    #레반슈타인->유사도 계산

    if not s1 and not s2:
        return 1.0
    s1 = s1 or ""
    s2 = s2 or ""

    m, n = len(s1), len(s2)
    if m < n:
        s1, s2 = s2, s1
        m, n = n, m

    max_len = max(m, n)
    if max_len == 0:
        return 1.0 
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            current = dp[j]
            dp[j] = min(dp[j] + 1,      
                        dp[j - 1] + 1,  
                        prev + cost)  
            prev = current
            
    distance = dp[n]
    
    similarity = 1.0 - (distance / max_len)
    return similarity


def extract_response_header_features(data):
    try:
        final_doc = data.get('data', {}).get('requests', [{}])[0]
        headers = final_doc.get('response', {}).get('response', {}).get('headers', {})
        headers_lower = {k.lower(): v for k, v in headers.items()}
    except (IndexError, AttributeError):
        print("응답 헤더 오류.")
        return [None] * 7 

    features = []

    features.append('x-frame-options' in headers_lower)
    features.append('strict-transport-security' in headers_lower)
    features.append('attachment' in headers_lower.get('content-disposition', '').lower())
    features.append('x-xss-protection' in headers_lower)
    features.append('content-security-policy' in headers_lower)
    features.append('x-content-type-options' in headers_lower)
    
    cookies = data.get('data', {}).get('cookies', [])
    cookie_security = True
    if not cookies:
        cookie_security = True
    else:
        for cookie in cookies:
            if not cookie.get('secure') or not cookie.get('httpOnly'):
                cookie_security = False
                break
    features.append(cookie_security)

    return features


def extract_request_header_features(data, whitelist_set):
    try:
        initial_url = data.get('task', {}).get('url')
        if not initial_url:
            return [None]
            
        initial_host = get_hostname(initial_url)
        initial_domain = tldextract.extract(initial_host).top_domain_under_public_suffix
        
        features = [initial_domain in whitelist_set]
        return features

    except Exception as e:
        print(f"피쳐 추출 오류: {e}")
        return [None]


def extract_mixed_header_features(data, whitelist_set):

    
    features = [None, None, None]
    
    try:
        initial_url = data.get('task', {}).get('url')
        final_url = data.get('page', {}).get('url')

        if not initial_url or not final_url:
            print("url 안찾아짐")
            return features

        initial_host = get_hostname(initial_url)
        final_host = get_hostname(final_url)
        
        if not initial_host:
             print(f"최초 호스트 오류: {initial_url})")
        if not final_host:
             print(f"최종 호스트 오류: {final_url})")

        initial_domain = tldextract.extract(initial_host).top_domain_under_public_suffix if initial_host else ""
        final_domain = tldextract.extract(final_host).top_domain_under_public_suffix if final_host else ""

    except Exception as e:
        print(f"추출 오류: {e}")
        return features # [None, None, None] 반환

    #  호스트 유사도 계산
    try:
        if initial_host is not None and final_host is not None:
            features[2] = levenshtein_similarity(initial_host, final_host)
        else:
            features[2] = None 
    except Exception as e:
        print(f"유사도 계산 오류: {e}")
        features[2] = None

    try:
        is_redirect = False
        if initial_domain and final_domain:
             is_redirect = (initial_domain != final_domain)
        elif initial_host != final_host: # 도메인이 없으면 호스트로 비교
             is_redirect = True

        host_whitelisted = initial_domain in whitelist_set if initial_domain else False
        location_whitelisted = final_domain in whitelist_set if final_domain else False

        if not is_redirect:
            features[0] = 'level0' # 리다이렉션 없음 (or 동일 도메인 내)
        elif host_whitelisted and location_whitelisted:
            features[0] = 'level0' # 화이트리스트 -> 화이트리스트
        elif host_whitelisted and not location_whitelisted:
            features[0] = 'level1' # 화이트리스트 -> 의심
        elif not host_whitelisted and not location_whitelisted:
            features[0] = 'level2' # 의심 -> 의심
        elif not host_whitelisted and location_whitelisted:
            features[0] = 'level3' # 의심 -> 화이트리스트
            
    except Exception as e:
        print(f"[ERROR] Redirection level 계산 중 오류: {e}")
        features[0] = None

    #홉카운트 계산하는 부분
    try:
        redirect_chain_urls = []

        #data['data']['requests'][i] 항목 중 request.primaryRequest == True 는 메인 프레임 문서
        primary_obj = None
        for r in data.get('data', {}).get('requests', []):
            req_obj = r.get('request', {})
            if (isinstance(req_obj, dict) and req_obj.get('primaryRequest')) or r.get('primaryRequest'):
                primary_obj = r
                break

        if primary_obj and isinstance(primary_obj.get('requests'), list):
            for hop in primary_obj.get('requests', []):
                hop_req = hop.get('request', {})
                url_val = None

                if isinstance(hop_req, dict):
                    url_val = hop_req.get('url')

                    if not url_val and isinstance(hop_req.get('request'), dict):
                        url_val = hop_req['request'].get('url')

                if url_val:
                    redirect_chain_urls.append(url_val)

        if not redirect_chain_urls:
            if initial_url:
                redirect_chain_urls.append(initial_url)
            if final_url and final_url != initial_url:
                redirect_chain_urls.append(final_url)

        hop_count_local = 0
        for i in range(len(redirect_chain_urls) - 1):
            h1 = get_hostname(redirect_chain_urls[i])
            h2 = get_hostname(redirect_chain_urls[i + 1])
            if h1 and h2 and h1 != h2:
                hop_count_local += 1

        features[1] = hop_count_local

    except Exception as e:
        print(f"홉카운트 오류: {e}", file=sys.stderr)
        features[1] = None
    print(redirect_chain_urls)
    return features

def extract_dom_features(dom_soup, data):
    if not dom_soup.body:
        print("이상한 dom")
        return [None] * 9

    features = []
    all_nodes = dom_soup.find_all(True)

    try:
        features.append(len(all_nodes)) # total_dom_nodes

        max_d = 0
        for node in all_nodes:
            depth = len(list(node.parents))
            if depth > max_d:
                max_d = depth
        features.append(max_d) # max_depth

        forms = dom_soup.find_all('form')
        features.append(len(forms)) # num_forms

        features.append(len(dom_soup.find_all('input', {'type': 'password'}))) # num_password_fields

        suspicious_form = False
        if forms:
            for form in forms:
                action = form.get('action', '').strip().lower()
                if not action or action == '#' or action.startswith('javascript:'):
                    suspicious_form = True
                    break
        features.append(suspicious_form) # form_action_suspicious

        features.append(len(dom_soup.find_all('iframe'))) # num_iframes

        js_redirect = False
        if dom_soup.find('meta', attrs={'http-equiv': re.compile(r'^refresh$', re.I)}):
            js_redirect = True
        else:
            scripts = dom_soup.find_all('script')
            for script in scripts:
                if script.string and ('window.location' in script.string or 'document.location' in script.string):
                    js_redirect = True
                    break
        features.append(js_redirect) # has_js_redirect

        page_domain = data.get('page', {}).get('domain')
        registered_page_domain = tldextract.extract(page_domain).top_domain_under_public_suffix
        
        links = dom_soup.find_all('a', href=True)
        external_count = 0
        if not links or not registered_page_domain:
            features.append(0.0) # percent_external_links
        else:
            for link in links:
                href = link['href']
                if href.startswith(('http://', 'https://')):
                    link_host = get_hostname(href)
                    link_domain = tldextract.extract(link_host).top_domain_under_public_suffix
                    if link_domain and link_domain != registered_page_domain:
                        external_count += 1
            features.append((external_count / len(links)) * 100 if len(links) > 0 else 0.0)

        hidden_count = 0
        hidden_style = dom_soup.find_all(style=re.compile(r'display:\s*none', re.I))
        hidden_count += len(hidden_style)
        hidden_type = dom_soup.find_all('input', {'type': 'hidden'})
        hidden_count += len(hidden_type)
        hidden_attr = dom_soup.find_all(hidden=True)
        hidden_count += len(hidden_attr)
        features.append(hidden_count) # num_hidden_elements

    except Exception as e:
        print(f"dom 피쳐 추출 중 오류: {e}")
        return [None] * 9

    return features


def extract_url_features(initial_url_from_csv):
    try:
        url = initial_url_from_csv.strip()
        parsed_url = urlparse(url)
        
        if not parsed_url.scheme:
            url = "http://" + url
            parsed_url = urlparse(url)
        
        hostname = parsed_url.hostname
        
        if not hostname:
            print(f"유효하지 않은 URL '{initial_url_from_csv}'")
            return [None] * 7
            
        ext = tldextract.extract(hostname)
        etld_plus_1 = ext.top_domain_under_public_suffix if ext.top_domain_under_public_suffix else hostname

        features = []

        features.append(len(hostname)) # hostname_length
        features.append(len(ext.subdomain.split('.')) if ext.subdomain else 0) # subdomain_depth
        
        try:
            ipaddress.ip_address(hostname)
            features.append(True) # has_ip_address
        except ValueError:
            features.append(False)
            
        special_chars = re.sub(r'[a-zA-Z0-9\.]', '', hostname)
        features.append(len(special_chars)) # num_special_chars
        features.append(ext.suffix) # tld
        features.append(calculate_entropy(etld_plus_1) if etld_plus_1 else 0.0) # domain_entropy
        
        has_path = bool(parsed_url.path and parsed_url.path != '/')
        has_query = bool(parsed_url.query)
        features.append(has_path or has_query) # has_query_or_path, 훈련에선 안씀

        return features

    except Exception as e:
        print(f"{e} 피쳐추출 오류, url: {initial_url_from_csv})")
        return [None] * 7


# --- 메인 추출 함수 ---

def get_features_for_sample(uuid, initial_url, whitelist_set):

    
    try:
        # 1. API 및 DOM 데이터 가져오기
        data = get_json(uuid)
        dom_raw = get_dom(uuid) 
        
        if not data or not dom_raw:
            print(f"[{uuid}] dom 에러.")
            return None
            
        dom_soup = BeautifulSoup(dom_raw, 'html.parser')

    except RequestException as e:
        print(f"[{uuid}] api 오류 {e}.")
        return None
    except Exception as e:
        print(f"[{uuid}] 무슨무슨 오류: {e}.")
        return None
    
    try:
        # CSV에서 들어온 initial_url을 호스트로 정규화
        # 예) "google.com" → "google.com" , "https://cmb-clients.com/index.html" → "cmb-clients.com"
        initial_url_host_only = get_hostname(initial_url) or (initial_url.strip() if isinstance(initial_url, str) else initial_url)

        features_response = extract_response_header_features(data)
        features_request = extract_request_header_features(data, whitelist_set)
        features_mixed = extract_mixed_header_features(data, whitelist_set) 
        features_dom = extract_dom_features(dom_soup, data)
        features_url = extract_url_features(initial_url_host_only) 
        
        # 3. 결과 행 조합
        feature_row = [uuid, initial_url_host_only] + features_response + features_request + features_mixed + features_dom + features_url
                      
        return feature_row

    except Exception as e:
        print(f"[{uuid}] 오류 발생: {e},생략")
        return None