import os
import csv
from urllib.parse import urlparse
import requests

from get_urlscan import get_latest_uuid  # 네가 만든 기존 파일의 함수 그대로 재사용


'''
LINK_CSV_PATH ="../data/nor/raw/top-1m.csv"        
UUID_CSV_PATH = "../data/nor/processed/nor_uuidlist.csv"       
'''


LINK_CSV_PATH ="../data/mal/raw/mallist.csv"        
UUID_CSV_PATH = "../data/mal/processed/mal_uuidlist.csv"      




INDEX_NO = 2311#시작 인덱스

ROW_LIMIT = 300# 데이터 몇개까지할지


def extract_host(raw_value):


    if not raw_value:
        return ""

    candidate = raw_value.strip()




    if "://" not in candidate:
        parsed = urlparse("http://" + candidate)
    else:
        parsed = urlparse(candidate)

    host = parsed.netloc if parsed.netloc else parsed.path.split("/")[0]

    # host가 'naver.com:80' 이런 케이스일 수도 있으니까 포트 잘라줌
    if ":" in host:
        host = host.split(":")[0]

    # 소문자로 통일
    host = host.lower()

    return host


def read_input_rows(path):

    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)

        # 헤더 읽기
        try:
            header = next(reader)
        except StopIteration:
            return  # 빈 파일이면 그냥 끝

        # 'url' 열 위치 찾기 (대소문자 구분 없이 url이라는 이름을 찾는다)
        url_col_idx = None
        for idx, colname in enumerate(header):
            if colname.strip().lower() == "url":
                url_col_idx = idx
                break

        if url_col_idx is None:
            raise RuntimeError("입력 CSV에 'url'이라는 컬럼이 없음")

        # 이제부터 실제 데이터 행
        data_row_number = 1  
        for row in reader:
            # row가 비거나 url_col_idx 범위 벗어나면 skip
            if not row or url_col_idx >= len(row):
                data_row_number += 1
                continue

            yield {
                "rownum": data_row_number,
                "link": row[url_col_idx].strip(),
            }
            data_row_number += 1


def ensure_output_file(path):

    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["uuid", "link"])


def append_result(path, uuid_value, link_value):

    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([uuid_value, link_value])


def main():
    ensure_output_file(UUID_CSV_PATH)

    processed_count = 0

    for item in read_input_rows(LINK_CSV_PATH):
        rownum = item["rownum"]
        link_raw = item["link"]

        if rownum < INDEX_NO:
            continue

        if ROW_LIMIT is not None and processed_count >= ROW_LIMIT:
            break

        host = extract_host(link_raw)
        if not host:

            append_result(UUID_CSV_PATH, "", link_raw)
            processed_count += 1
            continue

        #host를 기반으로 urlscan에서 최신 uuid 가져오기
        #  get_latest_uuid() 는 urlscan Search API를 호출해서 task.domain.keyword:"{host}" 로 가장 최근 스캔 1개를 size=1로 가져옴
        try:
            uuid_val = get_latest_uuid(host)
        except requests.exceptions.HTTPError as e:
            # api 많이 사용했을때
            if e.response is not None and e.response.status_code == 429:
                print("429 에러, api 과도사용.")
                return
            uuid_val = ""
            print(f"{host} uuid 조회 중 에러: {e}")
            continue
        except Exception as e:
            uuid_val = ""
            print(f"{host} uuid 조회 중 예외: {e}")
            continue

        if uuid_val is None:
            print(f"{link_raw} -> {host} -> no uuid, 스킵")
            continue


        append_result(UUID_CSV_PATH, uuid_val, link_raw)

        processed_count += 1

        print(f"[{processed_count}] {link_raw} -> {host} -> {uuid_val}")

    print(f"총 {processed_count}개 처리 완료")


if __name__ == "__main__":
    main()