"""Leakage-aware evaluation of the saved URL classifier on external labels."""

import argparse
import json
import math
from pathlib import Path
import sys
from typing import Any, Dict, Iterable, List, Sequence
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.calibration import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    log_loss,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.features.url_features import extract_features
from src.intelligence.brand_engine import analyze_brand
from src.intelligence.typosquatting import analyze_typosquatting
from src.intelligence.url_normalizer import normalize_url
from src.ml.predict import FEATURE_COLUMNS, model
from src.risk.policy import DEFAULT_RISK_POLICY


def binary_metrics(
    labels: Sequence[int],
    scores: Sequence[float],
    threshold: float,
) -> Dict[str, Any]:
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError("Threshold must be finite and in [0, 1]")
    y_true = np.asarray(labels, dtype=int)
    y_score = np.asarray(scores, dtype=float)
    if len(y_true) != len(y_score) or len(y_true) == 0:
        raise ValueError("Labels and scores must have the same non-zero length")
    if not np.isin(y_true, [0, 1]).all():
        raise ValueError("Labels must contain only 0 and 1")
    if not np.isfinite(y_score).all() or ((y_score < 0) | (y_score > 1)).any():
        raise ValueError("Scores must be finite values in [0, 1]")

    predictions = (y_score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(
        y_true,
        predictions,
        labels=[0, 1],
    ).ravel()
    has_both_classes = len(np.unique(y_true)) == 2
    return {
        "n": int(len(y_true)),
        "threshold": threshold,
        "precision": float(tp / (tp + fp)) if tp + fp else None,
        "recall": float(tp / (tp + fn)) if tp + fn else None,
        "f1": (
            float(2 * tp / (2 * tp + fp + fn))
            if 2 * tp + fp + fn
            else None
        ),
        "pr_auc_average_precision": (
            float(average_precision_score(y_true, y_score))
            if y_true.sum()
            else None
        ),
        "roc_auc": (
            float(roc_auc_score(y_true, y_score))
            if has_both_classes
            else None
        ),
        "brier_score": float(brier_score_loss(y_true, y_score)),
        "log_loss": float(log_loss(y_true, y_score, labels=[0, 1])),
        "false_positive_rate": (
            float(fp / (fp + tn))
            if fp + tn
            else None
        ),
        "false_negative_rate": (
            float(fn / (fn + tp))
            if fn + tp
            else None
        ),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
    }


def reliability_bins(
    labels: Sequence[int],
    scores: Sequence[float],
    bin_count: int = 10,
) -> List[Dict[str, Any]]:
    y_true = np.asarray(labels, dtype=int)
    y_score = np.asarray(scores, dtype=float)
    edges = np.linspace(0.0, 1.0, bin_count + 1)
    results = []
    for index in range(bin_count):
        included = (
            (y_score >= edges[index])
            & (
                (y_score <= edges[index + 1])
                if index == bin_count - 1
                else (y_score < edges[index + 1])
            )
        )
        if not included.any():
            continue
        results.append({
            "lower": float(edges[index]),
            "upper": float(edges[index + 1]),
            "count": int(included.sum()),
            "mean_score": float(y_score[included].mean()),
            "observed_positive_rate": float(y_true[included].mean()),
        })
    return results


def url_categories(url: str) -> List[str]:
    normalized = normalize_url(url)
    categories = []
    if analyze_brand(url).get("official_domain") is True:
        categories.append("official_domain")
    try:
        parsed = urlsplit(url if "://" in url else f"https://{url}")
        path = parsed.path
        path_parts = [
            part.lower()
            for part in path.split("/")
            if part
        ]
    except AttributeError:
        path_parts = []
    if any(part in {"redirect", "redirects", "redir"} for part in path_parts):
        categories.append("redirect_path")
    if analyze_typosquatting(url).get("possible_typosquatting") is True:
        categories.append("brand_lookalike")
    if not categories:
        categories.append("other")
    if not normalized.get("registered_domain"):
        return ["invalid_domain"]
    return categories


def _normalise_group(value: Any, url: str) -> str:
    if isinstance(value, str) and value.strip():
        candidate = value.strip().lower().rstrip(".")
        try:
            return normalize_url(candidate)["registered_domain"]
        except ValueError:
            pass
    return normalize_url(url)["registered_domain"]


def _read_training_groups(path: Path) -> set[str]:
    groups = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        groups.add(_normalise_group(value, value))
    if not groups:
        raise ValueError("Training-domain manifest is empty")
    return groups


def _predict_urls(urls: Sequence[str]) -> np.ndarray:
    feature_rows = [extract_features(url) for url in urls]
    frame = pd.DataFrame(feature_rows)
    missing = [name for name in FEATURE_COLUMNS if name not in frame.columns]
    if missing:
        raise ValueError(
            "Feature extractor does not provide manifest features: "
            + ", ".join(missing)
        )
    frame = frame.reindex(columns=FEATURE_COLUMNS)
    values = frame.to_numpy(dtype=float)
    if not np.isfinite(values).all():
        raise ValueError("Feature extraction produced non-finite values")
    return model.predict_proba(frame)[:, 1].astype(float)


def _fit_calibrators(
    labels: Sequence[int],
    scores: Sequence[float],
) -> Dict[str, Any]:
    y_true = np.asarray(labels, dtype=int)
    y_score = np.asarray(scores, dtype=float)
    if (
        len(y_true) < 400
        or np.bincount(y_true, minlength=2).min() < 100
    ):
        return {}
    clipped_logits = np.log(
        np.clip(y_score, 1e-6, 1 - 1e-6)
        / (1 - np.clip(y_score, 1e-6, 1 - 1e-6))
    ).reshape(-1, 1)
    sigmoid = LogisticRegression(solver="lbfgs", random_state=0)
    sigmoid.fit(clipped_logits, y_true)
    isotonic = IsotonicRegression(out_of_bounds="clip")
    isotonic.fit(y_score, y_true)
    return {
        "sigmoid": lambda values: sigmoid.predict_proba(
            np.log(
                np.clip(values, 1e-6, 1 - 1e-6)
                / (1 - np.clip(values, 1e-6, 1 - 1e-6))
            ).reshape(-1, 1)
        )[:, 1],
        "isotonic": isotonic.predict,
    }


def evaluate_dataset(
    dataset: pd.DataFrame,
    training_groups: Iterable[str],
    *,
    test_fraction: float = 0.5,
    thresholds: Sequence[float] = (0.5, 0.85),
) -> Dict[str, Any]:
    if not math.isfinite(test_fraction) or not 0.1 <= test_fraction <= 0.9:
        raise ValueError("test_fraction must be finite and in [0.1, 0.9]")
    if not thresholds or any(
        not math.isfinite(value) or not 0.0 <= value <= 1.0
        for value in thresholds
    ):
        raise ValueError("At least one finite threshold in [0, 1] is required")
    required = {"url", "label"}
    if not required.issubset(dataset.columns):
        raise ValueError("Evaluation CSV must contain url and label columns")
    frame = dataset.copy()
    frame = frame.dropna(subset=["url", "label"])
    frame["url"] = frame["url"].astype(str)
    frame = frame[frame["url"].str.strip().ne("")]
    labels = pd.to_numeric(frame["label"], errors="raise")
    if frame.empty or not labels.isin([0, 1]).all():
        raise ValueError("Evaluation data must have binary labels and valid rows")
    frame["label"] = labels.astype(int)
    training_group_set = set(training_groups)
    group_column = (
        frame["source_domain"]
        if "source_domain" in frame.columns
        else frame["url"]
    )
    frame["_domain_group"] = [
        _normalise_group(group, url)
        for group, url in zip(group_column, frame["url"])
    ]
    overlap = set(frame["_domain_group"]) & training_group_set
    if overlap:
        sample = sorted(overlap)[:5]
        raise ValueError(
            "Evaluation domains overlap model training domains: "
            + ", ".join(sample)
        )
    if frame["_domain_group"].nunique() < 2:
        raise ValueError("At least two distinct evaluation domains are required")

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=test_fraction,
        random_state=20261010,
    )
    calibration_indices, test_indices = next(
        splitter.split(
            frame,
            frame["label"],
            groups=frame["_domain_group"],
        )
    )
    calibration = frame.iloc[calibration_indices].copy()
    test = frame.iloc[test_indices].copy()
    calibration_groups = set(calibration["_domain_group"])
    test_groups = set(test["_domain_group"])
    if calibration_groups & test_groups:
        raise AssertionError("Calibration and test domains overlap")

    calibration_scores = _predict_urls(calibration["url"].tolist())
    test_scores = _predict_urls(test["url"].tolist())
    calibration_labels = calibration["label"].to_numpy()
    test_labels = test["label"].to_numpy()
    calibrators = _fit_calibrators(calibration_labels, calibration_scores)

    scores_by_method = {"raw": test_scores}
    for name, calibrator in calibrators.items():
        scores_by_method[name] = calibrator(test_scores)

    category_names = sorted({
        category
        for url in test["url"]
        for category in url_categories(url)
    })
    category_results = {}
    test_categories = [url_categories(url) for url in test["url"]]
    for category in category_names:
        mask = np.asarray([
            category in categories
            for categories in test_categories
        ])
        category_results[category] = {
            "n": int(mask.sum()),
            "metrics": {
                name: {
                    str(threshold): binary_metrics(
                        test_labels[mask],
                        scores[mask],
                        threshold=threshold,
                    )
                    for threshold in thresholds
                }
                for name, scores in scores_by_method.items()
                if mask.any()
            },
        }

    methods = {}
    for name, scores in scores_by_method.items():
        methods[name] = {
            "at_production_thresholds": {
                str(threshold): binary_metrics(
                    test_labels,
                    scores,
                    threshold=threshold,
                )
                for threshold in thresholds
            },
            "reliability_curve": reliability_bins(test_labels, scores),
        }
    source_confounded = None
    if "source" in frame.columns:
        source_label_counts = frame.groupby("source")["label"].nunique()
        source_confounded = bool((source_label_counts == 1).all())

    return {
        "status": "evaluated",
        "score_semantics": (
            "The raw XGBoost output is uncalibrated unless a calibration "
            "method is validated on the disjoint calibration and test sets."
        ),
        "split": {
            "strategy": (
                "training-domain manifest excluded; validation/calibration "
                "and test split by source-domain"
            ),
            "training_domains": len(training_group_set),
            "validation_calibration_rows": int(len(calibration)),
            "calibration_rows": int(len(calibration)),
            "test_rows": int(len(test)),
            "calibration_domains": int(len(calibration_groups)),
            "test_domains": int(len(test_groups)),
            "training_domains_manifest_checked": True,
            "groups_disjoint": True,
            "random_state": 20261010,
        },
        "source_label_perfectly_confounded": source_confounded,
        "calibration_fits": sorted(calibrators),
        "calibration_selection_note": (
            "A calibrator is supported only if it improves both Brier score "
            "and log loss on the untouched test split and the labels are "
            "representative. This utility does not persist calibrators."
        ),
        "test_methods": methods,
        "test_by_category": category_results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument(
        "--training-domains",
        type=Path,
        required=True,
        help="One model-training registered domain per line",
    )
    parser.add_argument("--test-fraction", type=float, default=0.5)
    parser.add_argument(
        "--thresholds",
        default=f"0.5,{DEFAULT_RISK_POLICY.ml_review_threshold}",
        help="Comma-separated classifier and risk-policy cutoffs",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 0.1 <= args.test_fraction <= 0.9:
        parser.error("--test-fraction must be in [0.1, 0.9]")
    try:
        thresholds = [float(value) for value in args.thresholds.split(",")]
        if not thresholds or any(
            not math.isfinite(value) or not 0 <= value <= 1
            for value in thresholds
        ):
            raise ValueError(
                "At least one threshold is required; values must be finite "
                "and in [0, 1]"
            )
        report = evaluate_dataset(
            pd.read_csv(args.dataset),
            _read_training_groups(args.training_domains),
            test_fraction=args.test_fraction,
            thresholds=thresholds,
        )
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    output = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
