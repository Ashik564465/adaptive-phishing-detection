from src.fusion.risk_fusion import RiskFusion
from src.rag.context_builder import ThreatContext
from src.pipeline.detection_pipeline import DetectionPipeline
from src.rag.context_builder import build_threat_context
from src.rag.retriever import RetrievedThreat


def test_pipeline_detects_high_risk_message():
    pipeline = DetectionPipeline(
        risk_fusion=RiskFusion()
    )

    context = build_threat_context(
        query_channel="EMAIL",
        retrieved_threats=[
            RetrievedThreat(
                document_id="historical-001",
                channel="EMAIL",
                label="phishing",
                text="Verify your account immediately.",
                similarity=0.95,
                sender=None,
                receiver=None,
            )
        ],
    )

    result = pipeline.detect(
        message_id="current-001",
        channel="EMAIL",
        phishing_probability=0.95,
        identity_risk=0.80,
        behavioral_risk=0.75,
        threat_context=context,
    )

    assert result.classification == "PHISHING"
    assert result.risk_score >= 70.0
    assert result.retrieved_threat_count == 1
    assert result.gemini_used is False


def test_pipeline_handles_text_only_sms():
    pipeline = DetectionPipeline(
        risk_fusion=RiskFusion()
    )

    result = pipeline.detect(
        message_id="sms-001",
        channel="SMS",
        phishing_probability=0.05,
        identity_risk=0.0,
        behavioral_risk=0.0,
    )

    assert result.classification == "SAFE"
    assert result.retrieved_threat_count == 0
    assert result.gemini_used is False


def test_pipeline_handles_empty_threat_memory():
    pipeline = DetectionPipeline(
        risk_fusion=RiskFusion()
    )

    result = pipeline.detect(
        message_id="email-001",
        channel="EMAIL",
        phishing_probability=0.60,
        identity_risk=0.20,
        behavioral_risk=0.30,
    )

    assert result.historical_risk == 0.0
    assert result.retrieved_threat_count == 0


def test_pipeline_rejects_invalid_channel():
    pipeline = DetectionPipeline(
        risk_fusion=RiskFusion()
    )

    try:
        pipeline.detect(
            message_id="msg-001",
            channel="UNKNOWN",
            phishing_probability=0.5,
        )
    except ValueError:
        return

    raise AssertionError(
        "Invalid channel should raise ValueError."
    )


def test_pipeline_rejects_invalid_probability():
    pipeline = DetectionPipeline(
        risk_fusion=RiskFusion()
    )

    try:
        pipeline.detect(
            message_id="msg-001",
            channel="EMAIL",
            phishing_probability=1.5,
        )
    except ValueError:
        return

    raise AssertionError(
        "Invalid probability should raise ValueError."
    )
def test_legitimate_only_history_has_zero_phishing_risk():
    context = ThreatContext(
        query_channel="SMS",
        retrieved_count=5,
        similar_phishing_count=0,
        similar_legitimate_count=5,
        average_similarity=0.90,
        evidence=[],
    )

    pipeline = DetectionPipeline(
        risk_fusion=RiskFusion()
    )

    result = pipeline.detect(
        message_id="test-legitimate-history",
        channel="SMS",
        phishing_probability=0.01,
        threat_context=context,
    )

    assert result.historical_risk == 0.0


def test_phishing_only_history_has_positive_risk():
    context = ThreatContext(
        query_channel="SMS",
        retrieved_count=5,
        similar_phishing_count=5,
        similar_legitimate_count=0,
        average_similarity=0.90,
        evidence=[],
    )

    pipeline = DetectionPipeline(
        risk_fusion=RiskFusion()
    )

    result = pipeline.detect(
        message_id="test-phishing-history",
        channel="SMS",
        phishing_probability=0.80,
        threat_context=context,
    )

    assert result.historical_risk > 0.0


def test_mixed_history_has_intermediate_risk():
    context = ThreatContext(
        query_channel="SMS",
        retrieved_count=5,
        similar_phishing_count=3,
        similar_legitimate_count=2,
        average_similarity=0.80,
        evidence=[],
    )

    pipeline = DetectionPipeline(
        risk_fusion=RiskFusion()
    )

    result = pipeline.detect(
        message_id="test-mixed-history",
        channel="SMS",
        phishing_probability=0.50,
        threat_context=context,
    )

    assert 0.0 < result.historical_risk < 1.0