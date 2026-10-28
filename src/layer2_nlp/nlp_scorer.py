from __future__ import annotations

from pathlib import Path

import pandas as pd
import torch

from src.layer2_nlp.transformer_classifier import (
	MAX_SEQUENCE_LENGTH,
	build_input_text,
	inference_output,
)


def score_message(model, tokenizer, message: pd.Series | dict, message_id: str) -> dict:
	text = build_input_text(message)
	encoded = tokenizer(
		text,
		return_tensors="pt",
		truncation=True,
		padding=True,
		max_length=MAX_SEQUENCE_LENGTH,
	)
	with torch.no_grad():
		logits = model(**encoded).logits
	probabilities = torch.softmax(logits, dim=-1)[0].tolist()
	return inference_output(message_id, str(message["channel"]), probabilities)
