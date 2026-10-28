"""AWS Lambda entry point for the existing FastAPI application."""

from mangum import Mangum

from src.api.main import app


handler = Mangum(app)
