FROM python:3.12-slim

WORKDIR /app
COPY scam_shield/ ./scam_shield/

ENTRYPOINT ["python", "-m", "scam_shield"]
CMD ["--help"]
