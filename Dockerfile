FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/root/.cache/huggingface \
    API_BASE_URL=http://127.0.0.1:8000

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.docker.txt .
RUN pip install --upgrade pip \
    && python -c "from pathlib import Path; p=Path('requirements.docker.txt'); lines=p.read_text(encoding='utf-8').splitlines(); p.write_text('\n'.join(line for line in lines if not line.startswith('torch==')), encoding='utf-8')" \
    && pip install -r requirements.docker.txt \
    && pip install --no-deps --index-url https://download.pytorch.org/whl/cpu torch==2.14.0+cpu

COPY src ./src
COPY ui ./ui
COPY models/phishing_classifier/config.json ./models/phishing_classifier/config.json
COPY models/phishing_classifier/model.safetensors ./models/phishing_classifier/model.safetensors
COPY models/phishing_classifier/special_tokens_map.json ./models/phishing_classifier/special_tokens_map.json
COPY models/phishing_classifier/tokenizer.json ./models/phishing_classifier/tokenizer.json
COPY models/phishing_classifier/tokenizer_config.json ./models/phishing_classifier/tokenizer_config.json
COPY models/phishing_classifier/vocab.txt ./models/phishing_classifier/vocab.txt
COPY data/processed/threat_memory_train_only.pkl ./data/processed/threat_memory_train_only.pkl
COPY docker/start.sh ./docker/start.sh

RUN chmod +x ./docker/start.sh \
    && mkdir -p ./data/processed

EXPOSE 8000 8501

ENTRYPOINT ["./docker/start.sh"]
