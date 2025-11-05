import pandas as pd

# 1) CSV 읽기: True/False를 실제 불리언으로 해석
df = pd.read_csv(
    "../data/mal/processed/new_mal_features.csv",
    true_values=["True"],
    false_values=["False"]
)

# 2) 분석에 의미 없는 식별자 컬럼은 제외(예: uuid)
cols = [c for c in df.columns if c != "uuid"]

# 3) 각 피쳐별 값의 빈도수 출력
freq_by_col = {}
for col in cols:
    counts = df[col].value_counts(dropna=False)  # NaN도 세고 싶으면 dropna=False
    freq_by_col[col] = counts

# 4) 보기 좋게 출력
for col, counts in freq_by_col.items():
    print(f"\n[{col}]")
    print(counts)