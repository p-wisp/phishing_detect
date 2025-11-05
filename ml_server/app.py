import json
import joblib  
import pandas as pd
from flask import Flask, request, jsonify

MODEL_PATH = "./models/phishing_model.pkl"
SCALER_PATH = "./models/scaler.pkl"





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
  "url_domain_entropy"
]

app = Flask(__name__)

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

LEVEL_MAP = {"level0": 0, "level1": 1, "level2": 2, "level3": 3} #리다이렉트 정보로 레벨링
BOOL_COLS = [ 
  "has_x_frame_options","has_strict_transport_security","has_content_disposition_attachment",
  "has_x_xss_protection","has_content_security_policy","has_x_content_type_options","has_cookie_security",
  "req_initial_host_in_whitelist","dom_form_action_suspicious","dom_has_js_redirect","url_has_ip_address"
]
CAT_COLS = ["url_tld"] 

@app.post("/predict") #라우터
def predict():
    data = request.get_json(force=True) or {}
    row = {k: data.get(k, None) for k in FEATURES}
    X = pd.DataFrame([row], columns=FEATURES)

    if "mixed_redirection_level" in X.columns:
        col = X["mixed_redirection_level"]
        if col.dtype == "object":
            X["mixed_redirection_level"] = col.map(LEVEL_MAP).fillna(0).astype("int8")
        else:
            X["mixed_redirection_level"] = pd.to_numeric(col, errors="coerce").fillna(0).astype("int8")



    for c in BOOL_COLS:
        if c in X.columns:
            X[c] = X[c].map(lambda v: 1 if str(v).lower() in ["1","true","t","yes","y"] else 0).astype("int8")



    for c in CAT_COLS:
        if c in X.columns:
            X[c] = pd.Categorical(X[c].astype(str).fillna("unknown"))

#결측치 0 혹시나
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

    #예측
    pred = int(model.predict(X)[0])

    return jsonify({"result": "phishing" if pred == 1 else "legit"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7001)