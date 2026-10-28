from __future__ import annotations

import json
import os
import sys
import re
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
	sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import torch

from src.config.settings import PHISHING_MODEL_PATH, PROCESSED_DATA_PATH, RANDOM_SEED
from src.layer2_nlp.transformer_classifier import evaluate_classifier, split_dataset, train_classifier


def main() -> None:
	if os.getenv("LAYER2_SMOKE_LIMIT"):
		raise RuntimeError("Full training requires LAYER2_SMOKE_LIMIT to be unset.")
	if not torch.cuda.is_available():
		raise RuntimeError("CUDA is required for full training; refusing CPU fallback.")

	frame = pd.read_parquet(PROCESSED_DATA_PATH / "unified_messages.parquet")
	train, validation, test = split_dataset(frame, seed=RANDOM_SEED)
	if len(train) + len(validation) + len(test) != len(frame):
		raise RuntimeError("Split rows do not account for the full processed dataset.")
	print(json.dumps({
		"dataset_rows": len(frame),
		"train_rows": len(train),
		"validation_rows": len(validation),
		"test_rows": len(test),
		"device": "cuda:0",
		"gpu": torch.cuda.get_device_name(0),
		"cuda": torch.version.cuda,
		"batch_size": 4,
		"eval_batch_size": 4,
		"gradient_accumulation_steps": 2,
		"max_sequence_length": 256,
		"fp16": True,
	}, indent=2))

	def distribution(partition: pd.DataFrame) -> dict:
		return {
			"samples": len(partition),
			"legitimate": int((partition["target"] == 0).sum()),
			"phishing": int((partition["target"] == 1).sum()),
			"channels": {
				channel: {
					"samples": int((partition["channel"] == channel).sum()),
					"legitimate": int(((partition["channel"] == channel) & (partition["target"] == 0)).sum()),
					"phishing": int(((partition["channel"] == channel) & (partition["target"] == 1)).sum()),
				}
				for channel in ("EMAIL", "SMS")
			},
		}

	start = time.perf_counter()
	trainer, config = train_classifier(train, validation, PHISHING_MODEL_PATH)
	training_seconds = time.perf_counter() - start
	metrics = {
		"overall": evaluate_classifier(trainer, test, "test"),
		"email": evaluate_classifier(trainer, test[test.channel == "EMAIL"], "email_test"),
		"sms": evaluate_classifier(trainer, test[test.channel == "SMS"], "sms_test"),
		"split_counts": {"train": len(train), "validation": len(validation), "test": len(test)},
		"split_distributions": {
			"train": distribution(train),
			"validation": distribution(validation),
			"test": distribution(test),
		},
		"config": config,
		"device": str(next(trainer.model.parameters()).device),
		"cuda": torch.version.cuda,
		"gpu": torch.cuda.get_device_name(0),
		"training_seconds": training_seconds,
		"smoke_limit": None,
	}
	test_metrics = metrics["overall"]
	predicted = test_metrics["predictions"]
	probabilities = test_metrics["probabilities"]
	prediction_artifact = test[["message_id", "channel"]].copy()
	prediction_artifact["actual_label"] = test["target"].astype(int).to_numpy()
	prediction_artifact["predicted_label"] = predicted
	prediction_artifact["phishing_probability"] = probabilities
	prediction_artifact["legitimate_probability"] = 1 - prediction_artifact["phishing_probability"]
	prediction_artifact.to_csv(PHISHING_MODEL_PATH / "test_predictions.csv", index=False)

	error_rows = test.assign(predicted_label=predicted, phishing_probability=probabilities)
	error_rows = error_rows[error_rows["target"] != error_rows["predicted_label"]].copy()
	def sanitize(value: object) -> str:
		text = "" if pd.isna(value) else str(value)
		text = re.sub(r"https?://\S+|www\.\S+", "[URL_REMOVED]", text)
		text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[EMAIL_REMOVED]", text)
		return text[:240]
	error_analysis = pd.DataFrame({
		"message_id": error_rows["message_id"].to_numpy(),
		"channel": error_rows["channel"].to_numpy(),
		"actual_label": error_rows["target"].astype(int).to_numpy(),
		"predicted_label": error_rows["predicted_label"].astype(int).to_numpy(),
		"phishing_probability": error_rows["phishing_probability"].to_numpy(),
		"error_type": [
			"false_positive" if actual == 0 else "false_negative"
			for actual in error_rows["target"]
		],
		"text_excerpt": [
			sanitize(f"{subject} {body}")
			for subject, body in zip(error_rows["subject"], error_rows["body"])
		],
	})
	error_analysis.to_csv(PHISHING_MODEL_PATH / "error_analysis.csv", index=False)
	metrics_for_file = json.loads(json.dumps(metrics))
	for result in (metrics_for_file["overall"], metrics_for_file["email"], metrics_for_file["sms"]):
		del result["predictions"]
		del result["probabilities"]
	(PHISHING_MODEL_PATH / "evaluation_metrics.json").write_text(
		json.dumps(metrics_for_file, indent=2), encoding="utf-8"
	)
	print(json.dumps(metrics_for_file, indent=2))


if __name__ == "__main__":
	main()
