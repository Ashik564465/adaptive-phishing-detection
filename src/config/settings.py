from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
EMAIL_INPUT_PATH = PROJECT_ROOT / "data" / "raw" / "email_combined.xlsx"
SMS_INPUT_PATH = PROJECT_ROOT / "data" / "raw" / "sms_combined.csv"
PROCESSED_DATA_PATH = PROJECT_ROOT / "data" / "processed"
METADATA_PATH = PROJECT_ROOT / "data" / "metadata"
PHISHING_MODEL_PATH = PROJECT_ROOT / "models" / "phishing_classifier"
EMBEDDING_CONFIG_PATH = PROJECT_ROOT / "models" / "embedding_config"

PHISHING_MODEL_NAME = "distilbert-base-uncased"
MAX_SEQUENCE_LENGTH = 256
TRAIN_BATCH_SIZE = 4
EVAL_BATCH_SIZE = 4
GRADIENT_ACCUMULATION_STEPS = 2
USE_FP16 = True
LEARNING_RATE = 2e-5
NUM_EPOCHS = 1
RANDOM_SEED = 42
TRAIN_RATIO = 0.70
VALIDATION_RATIO = 0.15
TEST_RATIO = 0.15

# Confirmed from the email dataset source before supervised model development:
# 0 represents safe/legitimate messages and 1 represents phishing/spam messages.
EMAIL_LABEL_MAPPING = {
	"0": "legitimate",
	"1": "phishing",
}

# Gemini configuration
GEMINI_API_KEY = None
GEMINI_MODEL_NAME = "gemini-3.6-flash"
GEMINI_ENABLED = False
GEMINI_MAX_OUTPUT_TOKENS = 512
GEMINI_TEMPERATURE = 0.0