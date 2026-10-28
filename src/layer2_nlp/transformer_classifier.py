from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (
	accuracy_score,
	confusion_matrix,
	precision_recall_fscore_support,
	roc_auc_score,
)
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset
from transformers import (
	AutoModelForSequenceClassification,
	AutoTokenizer,
	Trainer,
	TrainingArguments,
)

from src.config.settings import (
	EVAL_BATCH_SIZE,
	GRADIENT_ACCUMULATION_STEPS,
	LEARNING_RATE,
	MAX_SEQUENCE_LENGTH,
	NUM_EPOCHS,
	PHISHING_MODEL_NAME,
	RANDOM_SEED,
	TRAIN_BATCH_SIZE,
	USE_FP16,
)


LABEL_TO_ID = {"legitimate": 0, "phishing": 1}
ID_TO_LABEL = {value: key for key, value in LABEL_TO_ID.items()}


def set_seed(seed: int = RANDOM_SEED) -> None:
	random.seed(seed)
	np.random.seed(seed)
	torch.manual_seed(seed)
	if torch.cuda.is_available():
		torch.cuda.manual_seed_all(seed)


def build_input_text(row: pd.Series | dict) -> str:
	channel = str(row["channel"]).upper()
	body = "" if pd.isna(row.get("body")) else str(row.get("body"))
	if channel == "EMAIL":
		subject = "" if pd.isna(row.get("subject")) else str(row.get("subject"))
		return f"[CHANNEL] EMAIL [SUBJECT] {subject} [BODY] {body}".strip()
	if channel == "SMS":
		return f"[CHANNEL] SMS [BODY] {body}".strip()
	raise ValueError(f"Unsupported channel: {channel!r}")


def prepare_dataset(frame: pd.DataFrame) -> pd.DataFrame:
	required = {"message_id", "channel", "subject", "body", "label"}
	missing = sorted(required - set(frame.columns))
	if missing:
		raise ValueError(f"Layer 2 input is missing columns: {missing}")
	prepared = frame.copy()
	prepared["text"] = prepared.apply(build_input_text, axis=1)
	prepared["target"] = prepared["label"].map(LABEL_TO_ID)
	if prepared["target"].isna().any():
		raise ValueError("Layer 2 labels must be exactly legitimate/phishing.")
	return prepared


def _message_group(frame: pd.DataFrame) -> pd.Series:
	return frame["text"].str.casefold().str.replace(r"\s+", " ", regex=True).str.strip()


def split_dataset(
	frame: pd.DataFrame,
	*,
	seed: int = RANDOM_SEED,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
	prepared = prepare_dataset(frame).copy()
	prepared["duplicate_group"] = _message_group(prepared)
	groups = prepared[["duplicate_group", "target"]].drop_duplicates()
	def split_groups(values: pd.DataFrame, test_size: float):
		if len(values) < 2:
			return values.iloc[:0].copy(), values.copy()
		counts = values["target"].value_counts()
		stratify = values["target"] if len(counts) > 1 and counts.min() >= 2 else None
		return train_test_split(
			values,
			test_size=test_size,
			random_state=seed,
			stratify=stratify,
		)

	train_groups, heldout_groups = split_groups(groups, 0.30)
	validation_groups, test_groups = split_groups(heldout_groups, 0.50)
	assignments = {
		"train": set(train_groups["duplicate_group"]),
		"validation": set(validation_groups["duplicate_group"]),
		"test": set(test_groups["duplicate_group"]),
	}
	splits = tuple(
		prepared[prepared["duplicate_group"].isin(assignments[name])]
		.drop(columns="duplicate_group")
		.reset_index(drop=True)
		for name in ("train", "validation", "test")
	)
	return splits  # type: ignore[return-value]


class MessageDataset(Dataset):
	def __init__(self, frame: pd.DataFrame, tokenizer, max_length: int = MAX_SEQUENCE_LENGTH):
		self.labels = frame["target"].astype(int).tolist()
		self.encodings = tokenizer(
			frame["text"].tolist(),
			truncation=True,
			padding="max_length",
			max_length=max_length,
		)

	def __len__(self) -> int:
		return len(self.labels)

	def __getitem__(self, index: int) -> dict[str, torch.Tensor]:
		item = {key: torch.tensor(value[index]) for key, value in self.encodings.items()}
		item["labels"] = torch.tensor(self.labels[index], dtype=torch.long)
		return item


@dataclass(frozen=True)
class ModelConfig:
	model_name: str = PHISHING_MODEL_NAME
	max_sequence_length: int = MAX_SEQUENCE_LENGTH
	train_batch_size: int = TRAIN_BATCH_SIZE
	eval_batch_size: int = EVAL_BATCH_SIZE
	gradient_accumulation_steps: int = GRADIENT_ACCUMULATION_STEPS
	fp16: bool = USE_FP16
	learning_rate: float = LEARNING_RATE
	epochs: int = NUM_EPOCHS
	seed: int = RANDOM_SEED
	label_to_id: dict[str, int] | None = None

	def as_dict(self) -> dict:
		values = asdict(self)
		values["label_to_id"] = LABEL_TO_ID
		return values


def load_classifier(model_name: str = PHISHING_MODEL_NAME):
	tokenizer = AutoTokenizer.from_pretrained(model_name)
	model = AutoModelForSequenceClassification.from_pretrained(
		model_name,
		num_labels=2,
		id2label=ID_TO_LABEL,
		label2id=LABEL_TO_ID,
	)
	return tokenizer, model


def train_classifier(
	train_frame: pd.DataFrame,
	validation_frame: pd.DataFrame,
	output_dir: Path,
	*,
	config: ModelConfig | None = None,
) -> tuple[Trainer, dict]:
	config = config or ModelConfig()
	set_seed(config.seed)
	tokenizer, model = load_classifier(config.model_name)
	train_dataset = MessageDataset(train_frame, tokenizer, config.max_sequence_length)
	validation_dataset = MessageDataset(validation_frame, tokenizer, config.max_sequence_length)

	args = TrainingArguments(
		output_dir=str(output_dir / "checkpoints"),
		learning_rate=config.learning_rate,
		per_device_train_batch_size=config.train_batch_size,
		per_device_eval_batch_size=config.eval_batch_size,
		gradient_accumulation_steps=config.gradient_accumulation_steps,
		num_train_epochs=config.epochs,
		eval_strategy="epoch",
		save_strategy="epoch",
		load_best_model_at_end=True,
		metric_for_best_model="f1",
		greater_is_better=True,
		logging_strategy="epoch",
		report_to=[],
		seed=config.seed,
		data_seed=config.seed,
		fp16=config.fp16 and torch.cuda.is_available(),
	)

	def metrics(eval_prediction):
		probabilities = torch.softmax(torch.tensor(eval_prediction.predictions), dim=-1)[:, 1].numpy()
		predictions = (probabilities >= 0.5).astype(int)
		precision, recall, f1, _ = precision_recall_fscore_support(
			eval_prediction.label_ids, predictions, average="binary", zero_division=0
		)
		return {
			"accuracy": accuracy_score(eval_prediction.label_ids, predictions),
			"precision": precision,
			"recall": recall,
			"f1": f1,
			"roc_auc": roc_auc_score(eval_prediction.label_ids, probabilities),
		}

	trainer = Trainer(
		model=model,
		args=args,
		train_dataset=train_dataset,
		eval_dataset=validation_dataset,
		processing_class=tokenizer,
		compute_metrics=metrics,
	)
	trainer.train()
	output_dir.mkdir(parents=True, exist_ok=True)
	trainer.save_model(output_dir)
	tokenizer.save_pretrained(output_dir)
	(output_dir / "model_config.json").write_text(json.dumps(config.as_dict(), indent=2), encoding="utf-8")
	return trainer, config.as_dict()


def evaluate_classifier(trainer: Trainer, frame: pd.DataFrame, split_name: str) -> dict:
	dataset = MessageDataset(frame, trainer.processing_class, MAX_SEQUENCE_LENGTH)
	result = trainer.predict(dataset)
	probabilities = torch.softmax(torch.tensor(result.predictions), dim=-1)[:, 1].numpy()
	predictions = (probabilities >= 0.5).astype(int)
	precision, recall, f1, _ = precision_recall_fscore_support(
		frame["target"], predictions, average="binary", zero_division=0
	)
	return {
		"split": split_name,
		"samples": len(frame),
		"accuracy": accuracy_score(frame["target"], predictions),
		"precision": precision,
		"recall": recall,
		"f1": f1,
		"roc_auc": roc_auc_score(frame["target"], probabilities),
		"confusion_matrix": confusion_matrix(frame["target"], predictions).tolist(),
		"predictions": predictions.tolist(),
		"probabilities": probabilities.tolist(),
	}


def inference_output(message_id: str, channel: str, probabilities: list[float]) -> dict:
	if len(probabilities) != 2 or any(not 0 <= value <= 1 for value in probabilities):
		raise ValueError("probabilities must contain two values in [0, 1].")
	phishing_probability = float(probabilities[1])
	return {
		"message_id": message_id,
		"channel": channel.upper(),
		"phishing_probability": phishing_probability,
		"legitimate_probability": float(probabilities[0]),
		"nlp_risk": phishing_probability * 100,
		"predicted_label": int(phishing_probability >= 0.5),
	}
