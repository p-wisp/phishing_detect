import json
import sys
import pathlib
import joblib
import pandas as pd

from get_urlscan import get_json, get_dom, get_latest_uuid
from feature_extractor import get_features_for_sample, load_whitelist

MODEL_PATH = "../models/phishing_model.pkl"
SCALER_PATH = "../models/scaler.pkl"

FEATURES = [
    "has_x_frame_options",
    "has_strict_transport_security",
    "has_content_disposition_attachment",
    "has_x_xss_protection",
    "has_content_security_policy",
    "has_x_content_type_options",
    "has_cookie_security",
    "req_initial_host_in_whitelist",
    "mixed_redirection_level",
    "mixed_redirection_hop_count",
    "mixed_host_similarity",
    "dom_total_nodes",
    "dom_max_depth",
    "dom_num_forms",
    "dom_num_password_fields",
    "dom_form_action_suspicious",
    "dom_num_iframes",
    "dom_has_js_redirect",
    "dom_percent_external_links",
    "dom_num_hidden_elements",
    "url_hostname_length",
    "url_subdomain_depth",
    "url_has_ip_address",
    "url_num_special_chars",
    "url_tld",
    "url_domain_entropy",
]

LEVEL_MAP = {"level0": 0, "level1": 1, "level2": 2, "level3": 3}
BOOL_COLS = [
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
CAT_COLS = ["url_tld"]

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)


def _to_dataframe(features):
    """Build a single-row DataFrame in the exact FEATURE order."""
    row = {k: features.get(k, None) for k in FEATURES}
    return pd.DataFrame([row], columns=FEATURES)


def _preprocess(X):
    if "mixed_redirection_level" in X.columns:
        col = X["mixed_redirection_level"]
        if col.dtype == "object":
            X["mixed_redirection_level"] = col.map(LEVEL_MAP).fillna(0).astype("int8")
        else:
            X["mixed_redirection_level"] = pd.to_numeric(col, errors="coerce").fillna(0).astype("int8")

    for c in BOOL_COLS:
        if c in X.columns:
            X[c] = X[c].map(lambda v: 1 if str(v).lower() in ["1", "true", "t", "yes", "y"] else 0).astype("int8")

    for c in CAT_COLS:
        if c in X.columns:
            X[c] = pd.Categorical(X[c].astype(str).fillna("unknown"))

    for c in X.columns:
        if c in CAT_COLS:
            continue
        if c not in BOOL_COLS:
            if X[c].dtype == "object":
                X[c] = pd.to_numeric(X[c], errors="ignore")
        if pd.api.types.is_numeric_dtype(X[c]):
            if X[c].isna().any():
                X[c] = X[c].fillna(0)

    scale_cols = list(getattr(scaler, "feature_names_in_", []))
    if scale_cols:
        for c in scale_cols:
            if c not in X.columns:
                X[c] = 0.0
            if not pd.api.types.is_numeric_dtype(X[c]):
                X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0.0)
        X.loc[:, scale_cols] = scaler.transform(X[scale_cols])

    return X


def evaluate(features):
    X = _to_dataframe(features)
    X = _preprocess(X)
    pred = int(model.predict(X)[0])
    return "phishing" if pred == 1 else "legit"


def evaluate_with_json_result(features):
    return {"result": evaluate(features)}



if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python3 test.py <url-or-host>\n")
        sys.exit(2)

    target = sys.argv[1]

    try:
        uuid = get_latest_uuid(target)
        if not uuid:
            raise RuntimeError(f"No urlscan result for: {target}")
        data = get_json(uuid)
        dom = get_dom(uuid)
    except Exception as e:
        sys.stderr.write(f"[urlscan] failed: {e}\n")
        sys.exit(1)

    WHITELIST_FILE = '../data/whitelist.csv'
    try:
        whitelist_set = load_whitelist(WHITELIST_FILE)
    except Exception as e:
        sys.stderr.write(f"[whitelist] failed to load {WHITELIST_FILE}: {e}\n")
        whitelist_set = set()

    try:
        extracted = get_features_for_sample(uuid, target, whitelist_set)
    except Exception as e:
        sys.stderr.write(f"[extractor] failed: {e}\n")
        sys.exit(1)

    try:
        if isinstance(extracted, dict):
            feature_dict = {k: extracted.get(k) for k in FEATURES}
        elif isinstance(extracted, (list, tuple)):
            values = list(extracted)
            if len(values) >= 2 + len(FEATURES):
                values = values[2:2+len(FEATURES)]
            elif len(values) == len(FEATURES):
                pass
            else:
                raise ValueError(f"Extractor returned {len(values)} values; expected {len(FEATURES)} or at least {2+len(FEATURES)} with [uuid,host] prefix")
            feature_dict = dict(zip(FEATURES, values))
        else:
            raise TypeError("Unsupported extractor output (expected dict or list/tuple)")
    except Exception as e:
        sys.stderr.write(f"[features] normalize failed: {e}\n")
        sys.exit(1)

    try:
        result = evaluate_with_json_result(feature_dict)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as e:
        sys.stderr.write(f"[predict] failed: {e}\n")
        sys.exit(1)