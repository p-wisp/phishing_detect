import csv
import os
import sys

# 위에서 만든 feature_extractor.py에서 함수 임포트
from feature_extractor import get_features_for_sample, load_whitelist


#경로
'''
UUID_LIST_FILE = '../data/nor/processed/nor_uuidlist.csv'
WHITELIST_FILE = '../data/whitelist.csv'
OUTPUT_FEATURES_FILE = '../data/nor/processed/nor_features_neww.csv'
'''

UUID_LIST_FILE = '../data/mal/processed/mal_uuidlist.csv'
WHITELIST_FILE = '../data/whitelist.csv'
OUTPUT_FEATURES_FILE = '../data/mal/processed/mal_features.csv'

# 처리할 샘플 범위 (0번 인덱스부터 100개)
START_INDEX = 0
SAMPLE_COUNT = 2300



# CSV 헤더 정의 (요청대로 수정됨)
CSV_HEADER = [
    'uuid', 'url', # (참고: CSV에서 'link' 열을 읽지만, 여기서는 'url'로 저장)
    # 응답 헤더 기반 피쳐 
    'has_x_frame_options', 'has_strict_transport_security', 'has_content_disposition_attachment',
    'has_x_xss_protection', 'has_content_security_policy', 'has_x_content_type_options',
    'has_cookie_security',
    # 요청 헤더 기반 피쳐
    'req_initial_host_in_whitelist',
    # 요청/응답 혼합 기반 피쳐 
    'mixed_redirection_level', 'mixed_redirection_hop_count', 'mixed_host_similarity',
    # DOM 기반 피쳐 
    'dom_total_nodes', 'dom_max_depth', 'dom_num_forms', 'dom_num_password_fields',
    'dom_form_action_suspicious', 'dom_num_iframes', 'dom_has_js_redirect',
    'dom_percent_external_links', 'dom_num_hidden_elements',
    # URL 기반 피쳐 
    'url_hostname_length', 'url_subdomain_depth', 'url_has_ip_address',
    'url_num_special_chars', 'url_tld', 'url_domain_entropy', 'url_has_query_or_path'
]


def load_uuid_list(filepath):
 
    uuid_list = []
    if not os.path.exists(filepath):
        print(f"UUID 리스트 파일 '{filepath}' 없음", file=sys.stderr)
        sys.exit(1)

    try:
        with open(filepath, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
                header_lower = [h.lower().strip() for h in header]
                
                try:
                    uuid_idx = header_lower.index('uuid')
                    link_idx = header_lower.index('link')
                except ValueError as e:
                    print(f"'{filepath}'에 uuid/link 열 없음 (헤더: {header})", file=sys.stderr)
                    sys.exit(1)

            except StopIteration:
                print(f"UUID 리스트 파일 '{filepath}' 비었음", file=sys.stderr)
                sys.exit(1)
                
            # 데이터 읽기
            for row in reader:
                if len(row) > max(uuid_idx, link_idx):
                    uuid = row[uuid_idx].strip()
                    link = row[link_idx].strip()
                    if uuid and link:
                        uuid_list.append((uuid, link))
    except Exception as e:
        print(f"UUID 리스트 파일 '{filepath}' 로드 에러: {e}", file=sys.stderr)
        sys.exit(1)
        
    print(f"'{filepath}'에서 {len(uuid_list)}개 로드함")
    return uuid_list







def main():
    
    #화이트리스트 로드
    whitelist_set = load_whitelist(WHITELIST_FILE)
    
    #UUID 리스트 로드 
    uuid_list = load_uuid_list(UUID_LIST_FILE)

    end_index = min(START_INDEX + SAMPLE_COUNT, len(uuid_list))
    to_process = uuid_list[START_INDEX : end_index]
    
    if not to_process:
        print("처리할 샘플 없음 (시작 인덱스/샘플 수 확인)")
        return

    print(f"총 {len(to_process)}개 처리 시작 (인덱스 {START_INDEX}~{end_index-1})")


    try:
        output_dir = os.path.dirname(OUTPUT_FEATURES_FILE)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"출력 디렉터리 '{output_dir}' 생성함")

        file_exists = os.path.exists(OUTPUT_FEATURES_FILE)

        with open(OUTPUT_FEATURES_FILE, mode='a', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            
            if not file_exists:
                writer.writerow(CSV_HEADER)
                print(f"새 파일 '{OUTPUT_FEATURES_FILE}' 만들고 헤더 씀")
            else:
                print(f"기존 파일 '{OUTPUT_FEATURES_FILE}'에 추가함")

            processed_count = 0
            for i, (uuid, initial_url) in enumerate(to_process, start=1):
                print(f"처리 중 ({i}/{len(to_process)}): UUID {uuid}")
                
                # feature_extractor에서 피쳐 리스트 가져오기
                feature_row = get_features_for_sample(uuid, initial_url, whitelist_set)
                
                if feature_row:
                    writer.writerow(feature_row)
                    processed_count += 1
                else:
                    print(f"[{uuid}] 피처 추출 실패, csv 기록 안 함", file=sys.stderr)
 
    
    except IOError as e:
        print(f"출력 파일 '{OUTPUT_FEATURES_FILE}' 쓰기 에러: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"에러: {e}", file=sys.stderr)
        sys.exit(1)

    print("끝")
    print(f"총 {len(to_process)}개 시도, {processed_count}개 성공")
    print(f"결과 '{OUTPUT_FEATURES_FILE}'에 저장함")


if __name__ == "__main__":
    main()