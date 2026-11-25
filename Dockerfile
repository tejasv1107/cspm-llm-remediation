# Single image shared by both services in docker-compose.yml (dashboard, mlflow); the
# command each container runs is set per-service in the compose file, not here.
FROM python:3.12-slim

WORKDIR /app

# Build deps for any package without a prebuilt wheel on this platform, plus curl/unzip to fetch
# the validation toolchain below -- all removed after install to keep the image small.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl unzip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# rag_pipeline/validator.py's terraform -> tflint -> OPA chain needs all three binaries on PATH
# *inside this container* -- having them on the host (or a dev machine) is not enough, since the
# dashboard and any generation code run here, not on the host.
RUN curl -sSLo /tmp/terraform.zip https://releases.hashicorp.com/terraform/1.15.7/terraform_1.15.7_linux_amd64.zip \
    && unzip -q /tmp/terraform.zip -d /usr/local/bin \
    && curl -sSLo /tmp/tflint.zip https://github.com/terraform-linters/tflint/releases/latest/download/tflint_linux_amd64.zip \
    && unzip -q /tmp/tflint.zip -d /usr/local/bin \
    && curl -sSLo /usr/local/bin/opa https://github.com/open-policy-agent/opa/releases/latest/download/opa_linux_amd64_static \
    && chmod +x /usr/local/bin/opa \
    && rm -f /tmp/terraform.zip /tmp/tflint.zip \
    && apt-get purge -y build-essential curl unzip \
    && apt-get autoremove -y \
    && terraform version && tflint --version && opa version

COPY . .

EXPOSE 8501 5000
