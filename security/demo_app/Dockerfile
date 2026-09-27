# Image for the demo target, so Trivy has a container image to scan in CI.
# Uses a deliberately older base so Trivy reliably reports fixable CVEs in the demo.
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

EXPOSE 5001
CMD ["python", "app.py"]
