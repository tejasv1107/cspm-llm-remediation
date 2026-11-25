"""Validate generated Terraform: ``terraform validate`` -> ``tflint`` -> OPA, in sequence.

Every stage *fails closed*: if a required binary is missing the stage fails (it is never
silently skipped). After the first failing stage the remaining stages are marked
``skipped`` unless ``stop_on_failure=False``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import hcl2

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_DIR = REPO_ROOT / "opa_policies"
OPA_QUERY = "data.terraform.safety.deny"


@dataclass
class StageResult:
    """Outcome of one validation stage."""

    name: str
    passed: bool
    errors: list[str] = field(default_factory=list)
    skipped: bool = False


@dataclass
class ValidationResult:
    """Aggregate outcome of the whole pipeline."""

    stages: list[StageResult]

    @property
    def passed(self) -> bool:
        return all(s.passed for s in self.stages)

    @property
    def errors(self) -> list[str]:
        return [f"[{s.name}] {e}" for s in self.stages for e in s.errors]

    def stage(self, name: str) -> StageResult | None:
        return next((s for s in self.stages if s.name == name), None)


# ------------------------------------------------------------------ process helpers
def _binary(env_var: str, default: str) -> str | None:
    """Resolve a tool from ``$ENV_VAR`` (name or path) or PATH; ``None`` if absent."""
    return shutil.which(os.getenv(env_var, default))


def _run(cmd: list[str], cwd: Path, stdin: str | None = None, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd, cwd=cwd, input=stdin, capture_output=True, text=True, timeout=timeout, check=False
    )


def _missing(stage: str, env_var: str, default: str) -> StageResult:
    return StageResult(stage, False, [f"`{os.getenv(env_var, default)}` not found on PATH (set {env_var})"])


# --------------------------------------------------------------------------- stage 1
def run_terraform_validate(workdir: Path) -> StageResult:
    """``terraform init -backend=false`` then ``terraform validate -json``."""
    tf = _binary("TERRAFORM_BIN", "terraform")
    if tf is None:
        return _missing("terraform_validate", "TERRAFORM_BIN", "terraform")

    init = _run([tf, "init", "-backend=false", "-input=false", "-no-color"], workdir)
    if init.returncode != 0:
        return StageResult("terraform_validate", False, [f"init failed: {init.stderr.strip() or init.stdout.strip()}"])

    proc = _run([tf, "validate", "-json", "-no-color"], workdir)
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return StageResult("terraform_validate", False, [proc.stderr.strip() or proc.stdout.strip() or "no output"])
    errors = [
        f"{d.get('summary', '')}: {d.get('detail', '')}".strip(": ")
        for d in report.get("diagnostics", [])
        if d.get("severity") == "error"
    ]
    return StageResult("terraform_validate", bool(report.get("valid")) and not errors, errors)


# --------------------------------------------------------------------------- stage 2
def run_tflint(workdir: Path, config: Path | None = None) -> StageResult:
    """``tflint --format json``. Exit 2 = issues found, 1 = tflint itself failed."""
    tflint = _binary("TFLINT_BIN", "tflint")
    if tflint is None:
        return _missing("tflint", "TFLINT_BIN", "tflint")

    cmd = [tflint, "--format", "json"]
    config = config or (REPO_ROOT / ".tflint.hcl")
    if config.exists():
        cmd += ["--config", str(config)]
    proc = _run(cmd, workdir)
    if proc.returncode == 0:
        return StageResult("tflint", True)
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return StageResult("tflint", False, [proc.stderr.strip() or proc.stdout.strip() or "tflint failed"])
    errors = [
        f"{i['rule']['name']} (line {i.get('range', {}).get('start', {}).get('line', '?')}): {i['message']}"
        for i in report.get("issues", [])
    ]
    errors += [e.get("message", str(e)) for e in report.get("errors", [])]
    return StageResult("tflint", False, errors or ["tflint reported issues"])


# --------------------------------------------------------------------------- stage 3
def _unquote(value: Any) -> Any:
    """Undo python-hcl2's literal quoting and drop its ``__is_block__`` markers."""
    if isinstance(value, str) and len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    if isinstance(value, dict):
        return {_unquote(k): _unquote(v) for k, v in value.items() if k != "__is_block__"}
    if isinstance(value, list):
        return [_unquote(v) for v in value]
    return value


def _blocks(parsed: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for block in parsed.get(kind, []):
        for type_name, instances in block.items():
            for instance_name, config in instances.items():
                out.append({"type": _unquote(type_name), "name": _unquote(instance_name), "config": _unquote(config)})
    return out


def hcl_to_opa_input(hcl_text: str) -> dict[str, Any]:
    """Parse HCL into the ``{"resources": [...], "data": [...]}`` document the rego expects."""
    parsed = hcl2.loads(hcl_text)
    return {"resources": _blocks(parsed, "resource"), "data": _blocks(parsed, "data")}


def run_opa(hcl_text: str, policy_dir: Path = DEFAULT_POLICY_DIR) -> StageResult:
    """Evaluate ``terraform_safety.rego``; any ``deny`` message fails the stage."""
    opa = _binary("OPA_BIN", "opa")
    if opa is None:
        return _missing("opa", "OPA_BIN", "opa")
    try:
        document = hcl_to_opa_input(hcl_text)
    except Exception as exc:  # noqa: BLE001 - parser raises assorted lark errors
        return StageResult("opa", False, [f"could not parse HCL for policy evaluation: {exc}"])

    proc = _run(
        [opa, "eval", "--format", "json", "--stdin-input", "--data", str(policy_dir), OPA_QUERY],
        REPO_ROOT,
        stdin=json.dumps(document),
    )
    if proc.returncode != 0:
        return StageResult("opa", False, [proc.stderr.strip() or proc.stdout.strip() or "opa eval failed"])
    result = json.loads(proc.stdout).get("result", [])
    denials = sorted(result[0]["expressions"][0]["value"]) if result else []
    return StageResult("opa", not denials, denials)


# ------------------------------------------------------------------------ pipeline
def validate_hcl(
    hcl_text: str,
    policy_dir: Path = DEFAULT_POLICY_DIR,
    stop_on_failure: bool = True,
) -> ValidationResult:
    """Run the three stages in order against ``hcl_text``."""
    stages: list[StageResult] = []

    def _record(result: StageResult) -> None:
        stages.append(result)

    def _should_skip() -> bool:
        return stop_on_failure and any(not s.passed for s in stages)

    with tempfile.TemporaryDirectory(prefix="cspm-validate-") as tmp:
        workdir = Path(tmp)
        (workdir / "main.tf").write_text(hcl_text, encoding="utf-8")

        _record(run_terraform_validate(workdir))
        _record(StageResult("tflint", False, skipped=True) if _should_skip() else run_tflint(workdir))
        _record(StageResult("opa", False, skipped=True) if _should_skip() else run_opa(hcl_text, policy_dir))
    return ValidationResult(stages)


def summarise(result: ValidationResult) -> str:
    """Human-readable multi-line summary (used in PR bodies and logs)."""
    lines = []
    for s in result.stages:
        status = "SKIPPED" if s.skipped else ("PASS" if s.passed else "FAIL")
        lines.append(f"- {s.name}: {status}")
        lines += [f"    * {e}" for e in s.errors]
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    import sys

    outcome = validate_hcl(Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(summarise(outcome))
    raise SystemExit(0 if outcome.passed else 1)
