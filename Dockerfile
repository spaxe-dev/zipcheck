# Small, non-root image for scanning untrusted archives.
#
#   docker build -t zipcheck .
#   docker run --rm -v "$PWD:/data:ro" zipcheck /data/file.zip
#
# The container only needs the archive mounted read-only. zipcheck never writes
# extracted data, so the filesystem can be read-only as well:
#
#   docker run --rm --read-only -v "$PWD:/data:ro" zipcheck /data/file.zip

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE /app/
COPY src /app/src

RUN pip install --no-cache-dir .

RUN useradd --create-home --shell /usr/sbin/nologin scanner
USER scanner

ENTRYPOINT ["zipcheck"]
