FROM python:3.11-slim

# Arabic font for bilingual PDF reporting (Ch.5 5.6.5)
RUN apt-get update && apt-get install -y --no-install-recommends \
        fonts-kacst curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080
CMD ["uvicorn", "asaa.main:app", "--host", "0.0.0.0", "--port", "8080"]
