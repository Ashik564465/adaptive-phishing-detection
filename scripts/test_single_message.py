from __future__ import annotations


import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from src.config.settings import PHISHING_MODEL_PATH
from src.pipeline.detection_pipeline import DetectionPipeline
from src.fusion.risk_fusion import RiskFusion


def build_model_input(
    channel: str,
    subject: str = "",
    body: str = "",
) -> str:
    channel = channel.upper()

    if channel == "EMAIL":
        return (
            f"[CHANNEL] EMAIL "
            f"[SUBJECT] {subject} "
            f"[BODY] {body}"
        )

    if channel == "SMS":
        return (
            f"[CHANNEL] SMS "
            f"[BODY] {body}"
        )

    raise ValueError(
        "channel must be EMAIL or SMS."
    )


def predict_phishing_probability(
    model,
    tokenizer,
    text: str,
) -> float:
    device = torch.device(
        "cuda" if torch.cuda.is_available() else "cpu"
    )

    model.to(device)
    model.eval()

    encoded = tokenizer(
        text,
        truncation=True,
        max_length=256,
        return_tensors="pt",
    )

    encoded = {
        key: value.to(device)
        for key, value in encoded.items()
    }

    with torch.no_grad():
        outputs = model(**encoded)
        probabilities = torch.softmax(
            outputs.logits,
            dim=-1,
        )

    # Label mapping:
    # 0 = legitimate
    # 1 = phishing
    return float(
        probabilities[0, 1].item()
    )


def run_example(
    model,
    tokenizer,
    pipeline: DetectionPipeline,
    message_id: str,
    channel: str,
    subject: str,
    body: str,
):
    model_input = build_model_input(
        channel=channel,
        subject=subject,
        body=body,
    )

    phishing_probability = predict_phishing_probability(
        model=model,
        tokenizer=tokenizer,
        text=model_input,
    )

    result = pipeline.detect(
        message_id=message_id,
        channel=channel,
        phishing_probability=phishing_probability,
        identity_risk=0.0,
        behavioral_risk=0.0,
    )

    print("=" * 60)
    print(f"Message ID: {result.message_id}")
    print(f"Channel: {result.channel}")
    print(
        "Transformer phishing probability: "
        f"{result.phishing_probability:.4f}"
    )
    print(
        f"Historical risk: {result.historical_risk:.4f}"
    )
    print(f"Final risk score: {result.risk_score:.2f}")
    print(f"Classification: {result.classification}")
    print(
        f"Retrieved threats: "
        f"{result.retrieved_threat_count}"
    )
    print(f"Gemini used: {result.gemini_used}")

    print("Reasons:")
    for reason in result.explanation.evidence:
        print(f"  - {reason}")


def main():
    model_path = str(
        Path(PHISHING_MODEL_PATH)
    )

    print(f"Loading model from: {model_path}")

    tokenizer = AutoTokenizer.from_pretrained(
        model_path
    )

    model = AutoModelForSequenceClassification.from_pretrained(
        model_path
    )

    pipeline = DetectionPipeline(
        risk_fusion=RiskFusion()
    )

    run_example(
        model=model,
        tokenizer=tokenizer,
        pipeline=pipeline,
        message_id="demo-email-001",
        channel="EMAIL",
        subject="Urgent account verification required",
        body=(
            "Your account requires immediate verification. "
            "Please verify your account to avoid suspension."
        ),
    )

    run_example(
        model=model,
        tokenizer=tokenizer,
        pipeline=pipeline,
        message_id="demo-sms-001",
        channel="SMS",
        subject="",
        body="Team meeting is scheduled for tomorrow at 10 AM.",
    )


if __name__ == "__main__":
    main()