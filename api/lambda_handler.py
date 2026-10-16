import json

from src.risk.risk_engine import RiskEngine
from src.intelligence.url_normalizer import validate_url_input


# Load the engine once when the Lambda container starts.
# This allows AWS Lambda to reuse the loaded model/RAG system
# across warm invocations.
engine = RiskEngine()


def lambda_handler(event, context):
    try:
        if event.get("requestContext", {}).get("http", {}).get("method") == "OPTIONS":
            return response(204, {})
        body = event.get("body")

        if not body:
            return response(
                400,
                {"error": "Request body is required"}
            )

        # API Gateway normally sends body as a JSON string.
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                return response(
                    400,
                    {"error": "Invalid JSON body"}
                )

        if not isinstance(body, dict):
            return response(
                400,
                {"error": "Request body must be a JSON object"}
            )

        url = body.get("url")
        include_details = body.get("include_details", False)

        if not url or not isinstance(url, str):
            return response(
                400,
                {"error": "A valid 'url' field is required"}
            )

        url = url.strip()

        if not url:
            return response(
                400,
                {"error": "URL cannot be empty"}
            )
        if not isinstance(include_details, bool):
            return response(
                400,
                {"error": "'include_details' must be a boolean"}
            )
        try:
            validate_url_input(url)
        except ValueError as exc:
            return response(400, {"error": str(exc)})

        # Run the complete Adaptive Risk Engine.
        result = engine.evaluate_url(url)

        return response(
            200,
            result.to_combined_dict(include_details=include_details),
        )

    except Exception as exc:
        # Log the actual error to CloudWatch.
        print(f"Analysis error: {exc}")

        return response(
            500,
            {
                "error": "Internal analysis error"
            }
        )


def response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "POST,OPTIONS"
        },
        "body": json.dumps(
            body,
            ensure_ascii=False
        )
    }