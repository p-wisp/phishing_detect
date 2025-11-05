import json
import warnings
from itertools import product

import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,  
    classification_report,
)

import lightgbm as lgb
import os
import matplotlib.pyplot as plt


SEED = 42#시드값. 걍 의사난수로 함
MAX_TRIALS = 48  # 최대 시도 수(파라미터 조합 랜덤 서브샘플링)

DATA_MAL = "../data/mal/processed/new_mal_features.csv"
DATA_NOR = "../data/nor/processed/new_nor_features.csv"
MODELS_DIR = "../models"
SCALER_PKL = "../models/scaler.pkl"
MODEL_PKL = "../models/phishing_model.pkl"
FI_PNG = "../models/feature_importance.png"
REPORT_JSON = "../models/best_report.json"

os.makedirs(MODELS_DIR, exist_ok=True)



FEATURES = [
    # 응답 헤더 기반
    "has_x_frame_options",
    "has_strict_transport_security",
    "has_content_disposition_attachment",
    "has_x_xss_protection",
    "has_content_security_policy",
    "has_x_content_type_options",
    "has_cookie_security",
    # 요청 헤더 기반
    "req_initial_host_in_whitelist",
    # 혼합 기반
    "mixed_redirection_level",         # level0~3 -> 0~3
    "mixed_redirection_hop_count",
    "mixed_host_similarity",
    # DOM 기반
    "dom_total_nodes",
    "dom_max_depth",
    "dom_num_forms",
    "dom_num_password_fields",
    "dom_form_action_suspicious",
    "dom_num_iframes",
    "dom_has_js_redirect",
    "dom_percent_external_links",
    "dom_num_hidden_elements",
    #URL 기반
    "url_hostname_length",
    "url_subdomain_depth",
    "url_has_ip_address",
    "url_num_special_chars",
    "url_tld",                        
    "url_domain_entropy",
]

# 가중치 전용 열, 트란코 피시탱크 url 타입 차이때문에
WEIGHT_FLAG_COL = "url_has_query_or_path"

def _assert_columns(df, cols, name):
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise ValueError(f"{name}에 필요한 컬럼이 빠졌습니다: {missing}")


def _to_bool_int(series):
    """
    문자열 'True'/'False' 등을 안전하게 0/1로 변환.
    주의: pandas의 astype('bool')은 비어있지 않은 문자열을 True로 처리하므로
    문자열인 경우 먼저 명시적 매핑을 수행한다.
    """
    s = series.copy()
    if pd.api.types.is_string_dtype(s):
        s = s.astype(str).str.strip().str.lower().map({
            "true": True, "false": False,
            "1": True, "0": False, "yes": True, "no": False
        })
    # 숫자/불리언 섞인 경우도 처리
    s = s.replace({1: True, 0: False})
    return s.astype("bool").astype("int8")


def load_and_merge():
    if not os.path.exists(DATA_MAL) or not os.path.exists(DATA_NOR):
        raise FileNotFoundError(f"CSV 경로 확인: {DATA_MAL} / {DATA_NOR}")

    df_mal = pd.read_csv(DATA_MAL)
    df_nor = pd.read_csv(DATA_NOR)

    _assert_columns(df_mal, FEATURES, "mal_features.csv")
    _assert_columns(df_nor, FEATURES, "nor_features.csv")
    # 가중치 플래그는 없을 수도 있으므로 이후 처리에서 기본 False로 보정

    df_mal["target"] = 1
    df_nor["target"] = 0

    df = pd.concat([df_mal, df_nor], axis=0, ignore_index=True)

    # 가중치 플래그가 없으면 False로 채움
    if WEIGHT_FLAG_COL not in df.columns:
        warnings.warn(f"입력에 {WEIGHT_FLAG_COL} 컬럼이 없어 False로 대체합니다.")
        df[WEIGHT_FLAG_COL] = False

    return df


def preprocess_split(df, test_size=0.2):

    work = df.copy()
    if "mixed_redirection_level" in work.columns:
        map_lvl = {"level0": 0, "level1": 1, "level2": 2, "level3": 3}
        work["mixed_redirection_level"] = (
            work["mixed_redirection_level"]
            .astype(str).str.strip().str.lower()
            .map(map_lvl)
            .fillna(0)  # 리다이렉션 정보 누락/비정상 토큰은 level0으로 처리
            .astype("int8")
        )

    bool_like_cols = [
        "has_x_frame_options",
        "has_strict_transport_security",
        "has_content_disposition_attachment",
        "has_x_xss_protection",
        "has_content_security_policy",
        "has_x_content_type_options",
        "has_cookie_security",
        "req_initial_host_in_whitelist",
        "dom_form_action_suspicious",
        "dom_has_js_redirect",
        "url_has_ip_address",
    ]
    for c in bool_like_cols:
        if c in work.columns:
            work[c] = _to_bool_int(work[c])

    if "url_tld" in work.columns:
        work["url_tld"] = work["url_tld"].astype("category")

    for c in FEATURES:
        if c not in work.columns:
            continue
        if pd.api.types.is_numeric_dtype(work[c]):
            work[c] = work[c].fillna(work[c].median())
        elif pd.api.types.is_categorical_dtype(work[c]) or work[c].dtype == "object":
            work[c] = work[c].fillna(work[c].mode(dropna=True).iloc[0] if not work[c].mode(dropna=True).empty else "unknown")


    y = work["target"].astype("int8")
    wflag = work.get(WEIGHT_FLAG_COL, pd.Series(False, index=work.index)).astype(bool)

    X = work[FEATURES].copy()

    categorical_cols = [c for c in X.columns if pd.api.types.is_categorical_dtype(X[c])]
    numeric_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c]) and c not in categorical_cols]

    non_scaled_int_cols = [
        "has_x_frame_options",
        "has_strict_transport_security",
        "has_content_disposition_attachment",
        "has_x_xss_protection",
        "has_content_security_policy",
        "has_x_content_type_options",
        "has_cookie_security",
        "req_initial_host_in_whitelist",
        "dom_form_action_suspicious",
        "dom_has_js_redirect",
        "url_has_ip_address",
        "mixed_redirection_level",   
    ]




    scale_numeric_cols = [c for c in numeric_cols if c not in non_scaled_int_cols]

    X_train, X_valid, y_train, y_valid, wflag_train, wflag_valid = train_test_split(
        X, y, wflag, test_size=test_size, random_state=SEED, stratify=y
    )

    return X_train, X_valid, y_train, y_valid, wflag_train, scale_numeric_cols, categorical_cols, non_scaled_int_cols


def fit_transform_scaler(
    X_train,
    X_valid,
    scale_numeric_cols,
):
    """숫자형 일부에만 StandardScaler 적용."""
    scaler = StandardScaler()
    Xtr = X_train.copy()
    Xva = X_valid.copy()
    if scale_numeric_cols:
        scaler.fit(Xtr[scale_numeric_cols])
        Xtr.loc[:, scale_numeric_cols] = scaler.transform(Xtr[scale_numeric_cols])
        Xva.loc[:, scale_numeric_cols] = scaler.transform(Xva[scale_numeric_cols])
    return Xtr, Xva, scaler






def build_param_grid(pos_weight):


    grid = {
        "n_estimators": [400, 800],
        "num_leaves": [31, 63],
        "max_depth": [-1, 12],
        "learning_rate": [0.03, 0.07],
        "min_child_samples": [20, 60],
        "subsample": [0.8],
        "colsample_bytree": [0.8, 1.0],
        "reg_lambda": [0.0, 5.0],
        "scale_pos_weight": [1.0, float(pos_weight)],
    }
    keys = list(grid.keys())
    combos = []
    for values in product(*[grid[k] for k in keys]):
        combos.append({k: v for k, v in zip(keys, values)})

    # 대규모 그리드에서 시간 초과 방지: 무작위로 MAX_TRIALS개만 선택
    if len(combos) > MAX_TRIALS:
        rng = np.random.default_rng(SEED)
        idx = rng.choice(len(combos), size=MAX_TRIALS, replace=False)
        combos = [combos[i] for i in idx]
    return combos


def evaluate_scores(y_true, y_prob, threshold=0.5):
    y_pred = (y_prob >= threshold).astype(int)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    roc = roc_auc_score(y_true, y_prob)
    pr_auc = average_precision_score(y_true, y_prob)
    return {"precision": float(prec), "recall": float(rec), "f1": float(f1), "roc_auc": float(roc), "pr_auc": float(pr_auc)}


def plot_feature_importance(model, feature_names, out_path):
    imp = model.booster_.feature_importance(importance_type="gain")
    names = model.booster_.feature_name()
    order = np.argsort(imp)[::-1]
    imp_sorted = imp[order]
    names_sorted = [names[i] for i in order]

    plt.figure(figsize=(10, max(4, int(len(names_sorted) * 0.35))))
    plt.title("LightGBM Feature Importance (gain)")
    plt.barh(range(len(names_sorted)), imp_sorted[::-1])
    plt.yticks(range(len(names_sorted)), names_sorted[::-1])
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def main():
    df = load_and_merge()
    X_train, X_valid, y_train, y_valid, wflag_train, scale_numeric_cols, categorical_cols, _non_scaled = preprocess_split(df, test_size=0.2)

    alpha_grid = [0.0, 0.5, 1.0]  # 0=완전제거, 1=무가중치

    pos = int((y_train == 1).sum())
    neg = int((y_train == 0).sum())
    pos_weight = (neg / max(pos, 1)) if pos > 0 else 1.0

    #파라미터 그리드
    param_grid = build_param_grid(pos_weight)

    best = {
        "alpha": None,
        "params": None,
        "scores": None,
        "clf": None,
        "scaler": None,
    }

    total_trials = 0

    print(f"[INFO] Train size={len(X_train)}, Valid size={len(X_valid)}, pos={pos}, neg={neg}, pos_weight≈{pos_weight:.2f}")
    print(f"[INFO] Scale columns: {scale_numeric_cols}")
    print(f"[INFO] Categorical columns: {categorical_cols}")

    for alpha in alpha_grid:
        # 샘플 가중치 벡터 구성
        sw = np.where(wflag_train.values, alpha, 1.0).astype("float32")
        # 표준화
        Xtr_scaled, Xva_scaled, scaler = fit_transform_scaler(X_train, X_valid, scale_numeric_cols)
        # ※ Xtr_scaled/Xva_scaled가 DataFrame이므로 dtype 유지

        for params in param_grid:
            total_trials += 1

            clf = lgb.LGBMClassifier(
                objective="binary",
                n_jobs=-1,
                random_state=SEED,
                **params,
            )

            clf.fit(
                Xtr_scaled,
                y_train,
                sample_weight=sw,
                eval_set=[(Xva_scaled, y_valid)],
                eval_metric="auc",
                callbacks=[
                    lgb.early_stopping(stopping_rounds=25, first_metric_only=True, verbose=False),
                    lgb.log_evaluation(period=50),
                ],
            )

            y_prob = clf.predict_proba(Xva_scaled)[:, 1]
            scores = evaluate_scores(y_valid, y_prob, threshold=0.5)

            # 선택 기준: PR-AUC 우선, 동률이면 ROC-AUC
            is_better = False
            if best["scores"] is None:
                is_better = True
            else:
                b = best["scores"]
                if scores["pr_auc"] > b["pr_auc"] + 1e-8:
                    is_better = True
                elif abs(scores["pr_auc"] - b["pr_auc"]) <= 1e-8 and scores["roc_auc"] > b["roc_auc"] + 1e-8:
                    is_better = True

            if is_better:
                best.update({
                    "alpha": alpha,
                    "params": params,
                    "scores": scores,
                    "clf": clf,
                    "scaler": scaler,
                })

    print(f"[INFO] Total trials: {total_trials}")
    print("\n[BEST] ========")
    print(f"alpha (url_has_query_or_path weight) : {best['alpha']}")
    print(f"params : {json.dumps(best['params'], indent=2)}")
    print(f"scores : {json.dumps(best['scores'], indent=2)}")

    # 자세한 리포트 출력
    Xtr_scaled, Xva_scaled, scaler = fit_transform_scaler(X_train, X_valid, scale_numeric_cols)
    # 최적 알파로 가중치 재생성
    sw = np.where(df.loc[X_train.index, WEIGHT_FLAG_COL].astype(bool).values, best["alpha"], 1.0).astype("float32")

    final_clf = lgb.LGBMClassifier(
        objective="binary",
        n_jobs=-1,
        random_state=SEED,
        **best["params"],
    )
    final_clf.fit(
        Xtr_scaled, y_train,
        sample_weight=sw,
        eval_set=[(Xva_scaled, y_valid)],
        eval_metric="auc",
        callbacks=[
            lgb.early_stopping(stopping_rounds=25, first_metric_only=True, verbose=False),
            lgb.log_evaluation(period=50),
        ],
    )
    y_prob = final_clf.predict_proba(Xva_scaled)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    print("\n[VALID REPORT @ 0.5]")
    print(classification_report(y_valid, y_pred, digits=4))

    # scaler.pkl / phishing_model.pkl 저장
    joblib.dump(scaler, SCALER_PKL)
    joblib.dump(final_clf, MODEL_PKL)
    print(f"[SAVE] scaler -> {SCALER_PKL}")
    print(f"[SAVE] model  -> {MODEL_PKL}")


    plot_feature_importance(final_clf, list(X_train.columns), FI_PNG)
    print(f"[SAVE] feature importance -> {FI_PNG}")

    # 
    report = {
        "best_alpha": best["alpha"],
        "best_params": best["params"],
        "valid_scores_threshold_0_5": best["scores"],
        "train_size": int(len(X_train)),
        "valid_size": int(len(X_valid)),
        "scale_numeric_cols": scale_numeric_cols,
        "categorical_cols": categorical_cols,
        "seed": SEED,
        "data_paths": {
            "mal": str(DATA_MAL),
            "nor": str(DATA_NOR),
        },
        "artifacts": {
            "scaler": str(SCALER_PKL),
            "model": str(MODEL_PKL),
            "feature_importance_png": str(FI_PNG),
        },
    }
    with open(REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"[SAVE] report -> {REPORT_JSON}")


if __name__ == "__main__":
    main()