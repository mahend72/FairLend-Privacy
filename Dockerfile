# Minimal research-library container for FairLend-Privacy.
#
# fairlend is a Python library (CKKS-based privacy-preserving fairness
# auditing), not a web service or CLI application -- this repository does
# not implement one, so this image does not fake one either. It exists so
# `import fairlend` / `fairlend.secure_compute` are usable from a
# reproducible, dependency-pinned environment.
#
# Python 3.12 matches a version already exercised by this repository's
# test matrix (.github/workflows/tests.yml) and used by its release build
# job -- TenSEAL wheel availability was verified there before this image
# was built on top of it.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="FairLend-Privacy" \
      org.opencontainers.image.description="Privacy-preserving fairness auditing for lending decisions using CKKS homomorphic encryption." \
      org.opencontainers.image.source="https://github.com/mahend72/FairLend-Privacy" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Only what's needed to build/install the library itself -- no raw or
# processed data, no results/evaluation artifacts, no legacy code, no
# tests, no git history, no secrets/keys. See .dockerignore for the full
# exclusion list enforced on the build context.
COPY pyproject.toml README.md LICENCE.txt ./
COPY src ./src

RUN pip install --upgrade pip \
    && pip install . \
    && rm -rf /app/src /app/build \
    && useradd --create-home --uid 1000 fairlend

USER fairlend

# No application entry point is provided: fairlend is a library, not a
# service. The default command is an import smoke test.
CMD ["python", "-c", "import fairlend; print('FairLend-Privacy ready')"]
