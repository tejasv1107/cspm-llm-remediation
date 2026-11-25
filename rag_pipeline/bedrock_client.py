"""Generate Terraform (HCL) with Claude Sonnet 5 on Amazon Bedrock via ``invoke_model``.

Cost control: this is a templated/retrieval-augmented code-gen task, not open-ended reasoning,
so ``effort`` defaults to ``"low"`` (verified live: this drops thinking-token spend to zero on a
trivial prompt, versus non-zero thinking tokens at the default effort). Callers that need higher
quality on harder findings can override it via ``BEDROCK_EFFORT`` or the constructor argument.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# claude-3-sonnet-20240229-v1:0 (the model originally specified) has reached end-of-life on
# Bedrock (confirmed live: invoke_model returns ResourceNotFoundException). Current Claude models
# on Bedrock require an inference-profile-prefixed ID rather than the bare model ID -- see
# `aws bedrock list-inference-profiles`.
DEFAULT_MODEL_ID = "us.anthropic.claude-sonnet-5"
ANTHROPIC_VERSION = "bedrock-2023-05-31"
NO_SAFE_REMEDIATION = "NO_SAFE_REMEDIATION"
VALID_EFFORTS = {"low", "medium", "high", "xhigh", "max"}

_FENCE = re.compile(r"```(?:hcl|terraform|tf)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)


class BedrockGenerationError(RuntimeError):
    """Bedrock call failed or the model returned nothing usable."""


@dataclass
class GenerationResult:
    """A model response."""

    hcl: str                      # extracted code; empty when the model declined
    raw_text: str
    model_id: str
    stop_reason: str | None
    input_tokens: int
    output_tokens: int
    thinking_tokens: int = 0      # billed as output tokens; tracked separately to spot cost drift

    @property
    def declined(self) -> bool:
        return not self.hcl

    @property
    def estimated_cost_usd(self) -> float:
        """Rough cost at Claude Sonnet 5 Bedrock pricing ($2/$10 per MTok); for dashboards/logs."""
        return self.input_tokens * 2e-6 + self.output_tokens * 10e-6


def extract_hcl(text: str) -> str:
    """Pull the code out of the first fenced block; fall back to the whole reply.

    Returns ``""`` if the model answered ``NO_SAFE_REMEDIATION``.
    """
    if NO_SAFE_REMEDIATION in text and not _FENCE.search(text):
        return ""
    match = _FENCE.search(text)
    return (match.group(1) if match else text).strip()


class BedrockClient:
    """Thin wrapper around the ``bedrock-runtime`` Messages-API ``invoke_model`` call.

    ``max_calls`` is a cheap safety valve against runaway spend (a bug, a misconfigured loop, an
    unexpectedly large batch): once reached, every further call raises
    :class:`BedrockGenerationError` without touching the network. ``None`` (the default) means
    unlimited, matching today's behaviour; callers that want a cap pass an explicit number or set
    ``BEDROCK_MAX_CALLS``.
    """

    def __init__(
        self,
        model_id: str | None = None,
        region: str | None = None,
        max_tokens: int | None = None,
        effort: str | None = None,
        temperature: float | None = None,
        max_calls: int | None = None,
        client: Any | None = None,
    ) -> None:
        self.model_id = model_id or os.getenv("BEDROCK_MODEL_ID", DEFAULT_MODEL_ID)
        self.max_tokens = max_tokens or int(os.getenv("BEDROCK_MAX_TOKENS", "4096"))
        self.effort = effort or os.getenv("BEDROCK_EFFORT", "low")
        if self.effort not in VALID_EFFORTS:
            raise ValueError(f"effort must be one of {sorted(VALID_EFFORTS)}, got {self.effort!r}")
        # Omitted by default: current-generation models (Sonnet 5, Opus 5, Fable 5.1) reject
        # `temperature` outright (confirmed live: ValidationException "temperature is deprecated
        # for this model"). Only set this (constructor arg or BEDROCK_TEMPERATURE) for an older
        # model that still accepts it.
        env_temp = os.getenv("BEDROCK_TEMPERATURE")
        self.temperature = temperature if temperature is not None else (float(env_temp) if env_temp else None)
        env_cap = os.getenv("BEDROCK_MAX_CALLS")
        self.max_calls = max_calls if max_calls is not None else (int(env_cap) if env_cap else None)
        self.call_count = 0
        self._client = client or boto3.client(
            "bedrock-runtime",
            region_name=region or os.getenv("AWS_REGION", "ap-south-1"),
            config=Config(retries={"max_attempts": 5, "mode": "adaptive"}, read_timeout=120),
        )

    def build_body(self, system: str, user: str) -> dict[str, Any]:
        """Request body in the Anthropic Messages format that Bedrock expects."""
        body: dict[str, Any] = {
            "anthropic_version": ANTHROPIC_VERSION,
            "max_tokens": self.max_tokens,
            "output_config": {"effort": self.effort},
            "system": system,
            "messages": [{"role": "user", "content": [{"type": "text", "text": user}]}],
        }
        if self.temperature is not None:
            body["temperature"] = self.temperature
        return body

    def generate(self, system: str, user: str) -> GenerationResult:
        """Invoke the model and return the generated HCL.

        Throttling and timeouts are retried by botocore's adaptive retry mode; any other
        ``ClientError`` (access denied, model not enabled, validation) surfaces as
        :class:`BedrockGenerationError`. Callers should check cheaper conditions first (urgency,
        retrieval, an existing PR for this finding) so this -- the only step with a per-call AWS
        cost -- only runs when a remediation is actually going to be produced.
        """
        if self.max_calls is not None and self.call_count >= self.max_calls:
            raise BedrockGenerationError(f"max_calls={self.max_calls} reached; refusing further Bedrock calls")
        self.call_count += 1

        try:
            response = self._client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(self.build_body(system, user)),
                contentType="application/json",
                accept="application/json",
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            logger.error("Bedrock invoke_model failed (%s) for %s", code, self.model_id)
            raise BedrockGenerationError(f"Bedrock error {code}: {exc}") from exc

        payload = json.loads(response["body"].read())
        text = "".join(b.get("text", "") for b in payload.get("content", []) if b.get("type") == "text")
        if not text.strip():
            raise BedrockGenerationError("Model returned an empty response")
        usage = payload.get("usage", {})
        return GenerationResult(
            hcl=extract_hcl(text),
            raw_text=text,
            model_id=self.model_id,
            stop_reason=payload.get("stop_reason"),
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            thinking_tokens=int(usage.get("output_tokens_details", {}).get("thinking_tokens", 0)),
        )


if __name__ == "__main__":  # pragma: no cover
    print(BedrockClient().build_body("system prompt", "user prompt"))
