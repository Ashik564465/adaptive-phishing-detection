import json
import math
from pathlib import Path

import pandas as pd
from xgboost import DMatrix, XGBClassifier

from src.features.url_features import extract_features


# --------------------------------------------------
# Paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[2]

MODEL_PATH = BASE_DIR / "models" / "xgboost_url_classifier.json"
FEATURE_COLUMNS_PATH = BASE_DIR / "models" / "feature_columns.json"


# --------------------------------------------------
# Load model
# --------------------------------------------------

model = XGBClassifier()

model.load_model(str(MODEL_PATH))


# --------------------------------------------------
# Load exact feature order
# --------------------------------------------------

with open(FEATURE_COLUMNS_PATH, "r") as f:
    FEATURE_COLUMNS = json.load(f)

booster_feature_names = model.get_booster().feature_names
if booster_feature_names is not None and booster_feature_names != FEATURE_COLUMNS:
    raise RuntimeError(
        "The saved model feature order does not match feature_columns.json"
    )


# --------------------------------------------------
# Prediction
# --------------------------------------------------

def predict_url(url: str):

    features = extract_features(url)
    missing_features = [
        name for name in FEATURE_COLUMNS
        if name not in features
    ]
    if missing_features:
        raise ValueError(
            "Feature extraction omitted model features: "
            + ", ".join(missing_features)
        )

    # Convert dictionary to DataFrame
    X = pd.DataFrame([features])

    # Ensure exact feature order
    X = X.reindex(columns=FEATURE_COLUMNS)
    try:
        X = X.astype(float)
    except (TypeError, ValueError) as exc:
        raise ValueError("Extracted model features must be numeric") from exc
    if not all(
        math.isfinite(value)
        for value in X.to_numpy().ravel()
    ):
        raise ValueError(
            "Extracted model features must be finite numeric values"
        )

    # Get phishing probability
    probability = float(
        model.predict_proba(X)[0][1]
    )
    contributions = model.get_booster().predict(
        DMatrix(X),
        pred_contribs=True,
    )[0]
    feature_contributions = [
        {
            "feature": feature,
            "value": float(X.iloc[0][feature]),
            "contribution": float(contribution),
        }
        for feature, contribution in zip(
            FEATURE_COLUMNS,
            contributions[:-1],
        )
    ]
    top_contributions = sorted(
        feature_contributions,
        key=lambda item: abs(item["contribution"]),
        reverse=True,
    )[:5]

    prediction = int(
        probability >= 0.5
    )

    return {
        "url": url,
        "prediction": prediction,
        "label": (
            "phishing"
            if prediction == 1
            else "legitimate"
        ),
        "label_semantics": (
            "Legacy thresholded model label at 0.5; not a confirmed incident "
            "or validated calibrated classification"
        ),
        "phishing_probability": probability,
        "raw_model_score": probability,
        "score_semantics": (
            "XGBoost predict_proba output; calibration has not been validated "
            "and this is not a calibrated probability"
        ),
        "top_feature_contributions": top_contributions,
    }


# --------------------------------------------------
# Local test
# --------------------------------------------------

if __name__ == "__main__":

    test_urls = [
        "https://google.com",
        "https://accounts.google.com",
        "https://google.com.evil.com/login",
        "https://gooogle.com",
    ]

    for url in test_urls:

        result = predict_url(url)

        print("\nURL:", result["url"])
        print("Prediction:", result["label"])
        print(
            "Phishing probability:",
            round(
                result["phishing_probability"],
                6
            )
        )