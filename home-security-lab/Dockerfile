# One image for the lab's Python services: shipper, detector, summarizer.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY homelab/ homelab/
COPY elastic/ elastic/
COPY sigma/ sigma/
RUN useradd --create-home --uid 10001 lab
USER lab
ENV PYTHONUNBUFFERED=1
