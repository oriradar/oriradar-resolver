# --- Rust: orifold + oriseek ---
FROM rust:1.94-bookworm AS rust-builder

WORKDIR /build
COPY crates/orifold /build/crates/orifold
COPY crates/oriseek /build/crates/oriseek

WORKDIR /build/crates/orifold
RUN cargo build --release

WORKDIR /build/crates/oriseek
RUN cargo build --release

# --- Python: oritypo-solver ---
FROM python:3.12-slim-bookworm

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ORIFOLD_PATH=/usr/local/bin/orifold \
    ORISEEK_PATH=/usr/local/bin/oriseek \
    ORI_MAX_VARIANTS=500

RUN useradd --create-home --uid 10001 appuser

COPY --from=rust-builder /build/crates/orifold/target/release/orifold /usr/local/bin/orifold
COPY --from=rust-builder /build/crates/oriseek/target/release/oriseek /usr/local/bin/oriseek

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

COPY backend/oritypo_solver ./oritypo_solver
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

CMD ["uvicorn", "oritypo_solver.main:app", "--host", "0.0.0.0", "--port", "8000"]
