#!/bin/sh
set -eu

uvicorn src.api.main:app --host 0.0.0.0 --port 8000 &
api_pid=$!
streamlit_pid=

cleanup() {
    if [ -n "$streamlit_pid" ]; then
        kill "$streamlit_pid" 2>/dev/null || true
    fi
    kill "$api_pid" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

attempt=0
until python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 90 ]; then
        echo "FastAPI did not become healthy." >&2
        exit 1
    fi
    if ! kill -0 "$api_pid" 2>/dev/null; then
        echo "FastAPI exited before becoming healthy." >&2
        wait "$api_pid"
        exit 1
    fi
    sleep 2
done

streamlit run ui/app.py \
    --server.address 0.0.0.0 \
    --server.port 8501 \
    --server.headless true &
streamlit_pid=$!

while kill -0 "$api_pid" 2>/dev/null && kill -0 "$streamlit_pid" 2>/dev/null; do
    sleep 2
done

if ! kill -0 "$api_pid" 2>/dev/null; then
    echo "FastAPI exited unexpectedly." >&2
    wait "$api_pid"
fi

echo "Streamlit exited unexpectedly." >&2
wait "$streamlit_pid"
