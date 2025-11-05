import os
import sys
import json
import requests
from bs4 import BeautifulSoup  
from urllib.parse import urlparse

API_KEY = ""#api 키 삽입
BASE    = "https://urlscan.io/api/v1"

def get_latest_uuid(domain):
    params = {"q": f'task.domain.keyword:"{domain}"', "size": 1}
    headers = {"API-Key": API_KEY}
    resp = requests.get(f"{BASE}/search/", params=params,
                        headers=headers, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("results"):
        return None
    return data["results"][0]["task"]["uuid"]
    

def get_json(uuid):
    result_url = f"{BASE}/result/{uuid}/"
    headers = {"API-Key": API_KEY}
    resp = requests.get(result_url, headers=headers, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    #final_url = data.get("page", {}).get("url")
    '''
    try:
        final_url= data["page"]["url"] 
    except KeyError:
        print("최종 url에 대한 객체가 없음")
    '''
    return data


def get_dom(uuid):

    dom_url = f"https://urlscan.io/dom/{uuid}/"
    headers = {"API-Key": API_KEY}
    resp = requests.get(dom_url, headers=headers, timeout=20)
    resp.raise_for_status()   # 200이 아니면 예외 → 버킷 미차감이므로 문제 추적 쉬움
    dom_pretty = BeautifulSoup(resp.text, "html.parser").prettify()

    return dom_pretty




if __name__ == "__main__":
    '''
    url=sys.argv[1]
    input_domain = url.strip().lower()

    uuid = None
    uuid = get_latest_uuid(input_domain)
    if uuid:
        #used_domain = cand
        print(f"{input_domain}에 대한 결과 확인")

    if uuid is None:
        print(f"[-] {input_domain} 에 대한 스캔 결과가 없음.")
        sys.exit("종료") 
    

    data = get_json(uuid)
    final_url=data["page"]["url"]
    print(f"final_url = {final_url}")
    jsondata = json.dumps(data, indent=2, ensure_ascii=False)
    print(get_dom(uuid))
    '''
    print(get_latest_uuid("apple.com"))