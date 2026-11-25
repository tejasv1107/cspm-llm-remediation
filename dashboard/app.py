"""Streamlit dashboard: fleet-wide posture, finding exploration, classifier transparency, a
live AI-remediation demo and remediation-pipeline status across clients.

Run with:  streamlit run dashboard/app.py

Data comes from ``data/anonymised/findings.jsonl`` (one FindingRecord per line) when present;
otherwise a deterministic demo dataset is generated so the UI always renders. Client labels come
from ``CLIENT_ACCOUNT_IDS`` (real AWS account IDs); the findings themselves stay synthetic unless
a real pipeline run has populated ``data/anonymised/``.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make the repo root importable when launched via `streamlit run dashboard/app.py`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import plotly.graph_objects as go  # noqa: E402
import streamlit as st  # noqa: E402

from classifier.labeller import URGENCY_ORDER, Urgency, label_finding  # noqa: E402
from ingestion.anonymiser import hash_account_id  # noqa: E402
from ingestion.schema import AccountTier, FindingRecord, Severity, WorkflowStatus  # noqa: E402

PROJECT_BADGE = "ICSPM"
PROJECT_TITLE_FULL = (
    "An Intelligent Cloud Security Posture Management Framework Using Machine Learning "
    "Classification and Retrieval-Augmented Generation for Automated Infrastructure-as-Code "
    "Remediation"
)
TAGLINE = (
    "Security Hub ingestion &rarr; XGBoost + SHAP urgency classification &rarr; "
    "RAG-generated Terraform remediation &rarr; human-approved GitHub PR"
)
MAX_LIVE_GENERATIONS_PER_SESSION = 5  # real Bedrock calls cost money; cap runaway clicking

FINDINGS_PATH = Path("data/anonymised/findings.jsonl")
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
SEVERITY_WEIGHT = {"CRITICAL": 10.0, "HIGH": 5.0, "MEDIUM": 2.0, "LOW": 0.5, "INFORMATIONAL": 0.0}
CLOSED = {"RESOLVED", "SUPPRESSED"}

# --- validated reference palette (see dataviz skill: references/palette.md) -----------------
SURFACE, PAGE, INK, MUTED, GRID, BASELINE_AXIS = (
    "#fcfcfb", "#f9f9f7", "#0b0b0b", "#52514e", "#e1e0d9", "#c3c2b7",
)
# Status palette (reserved; always paired with an icon/label, never used bare).
STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}
# Severity -> status colour. INFORMATIONAL carries no risk, so it gets muted ink rather than a
# reserved status colour (there are 5 severities and only 4 status steps).
SEVERITY_COLOUR = {
    "CRITICAL": STATUS["critical"], "HIGH": STATUS["serious"],
    "MEDIUM": STATUS["warning"], "LOW": STATUS["good"], "INFORMATIONAL": "#898781",
}
URGENCY_COLOUR = {
    Urgency.REMEDIATE_NOW.value: STATUS["critical"], Urgency.REMEDIATE_7D.value: STATUS["serious"],
    Urgency.MONITOR.value: STATUS["warning"], Urgency.SUPPRESS.value: STATUS["good"],
}
# Sequential ramps (light -> dark) for magnitude encodings.
BLUE_SCALE = [[0.0, "#cde2fb"], [0.25, "#86b6ef"], [0.5, "#3987e5"], [0.75, "#1c5cab"], [1.0, "#0d366b"]]
BLUE_SOLID, ORANGE_SOLID = "#2a78d6", "#eb6834"  # categorical slots 1 & 2
# Ordinal stage colours: nothing lighter than step 250 so every bar stays visible.
STAGE_COLOURS = ["#86b6ef", "#3987e5", "#256abf", "#184f95"]
CHART_FONT = {"family": "system-ui, -apple-system, 'Segoe UI', sans-serif", "color": MUTED}

RULE_DESCRIPTIONS = {
    "R0": "Already closed (resolved or suppressed)",
    "E1": "escalated: same control recurring 5+ times in this account",
    "E2": "escalated: open on a production account for 90+ days",
}

SAMPLE_DANGEROUS_HCL = """\
resource "aws_security_group" "demo" {
  name = "demo"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "demo" {
  bucket        = "demo-bucket"
  force_destroy = true
}

data "aws_iam_policy_document" "demo" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}
"""


# ------------------------------------------------------------------------- data
@dataclass
class Dataset:
    """Both the flattened DataFrame the UI renders and the FindingRecords it was built from."""

    frame: pd.DataFrame
    records: list[FindingRecord]


def demo_findings_records(client_ids: list[str], per_client: int = 150, seed: int = 7) -> list[FindingRecord]:
    """Deterministic synthetic findings for every client (used when no real data exists)."""
    rng = np.random.default_rng(seed)
    types = ["AwsS3Bucket", "AwsEc2SecurityGroup", "AwsIamUser", "AwsCloudTrailTrail",
             "AwsEc2Volume", "AwsAccount", "AwsEc2Vpc", "AwsGuardDutyDetector"]
    controls = ["S3.8", "EC2.13", "IAM.7", "CloudTrail.1", "EC2.7", "EC2.6", "GuardDuty.1", ""]
    now = datetime.now(timezone.utc)
    out: list[FindingRecord] = []
    for cid in client_ids:
        pseudonym = hash_account_id(cid)
        for i in range(per_client):
            created = now - timedelta(days=float(rng.exponential(25)))
            out.append(
                FindingRecord(
                    finding_id=f"demo-{pseudonym}-{i}",
                    account_id=pseudonym,
                    severity=Severity(str(rng.choice(SEVERITIES, p=[0.08, 0.27, 0.35, 0.22, 0.08]))),
                    title="demo finding",
                    resource_type=str(rng.choice(types)),
                    resource_arn=f"arn:aws:s3:::demo-{i}",
                    region=str(rng.choice(["ap-south-1", "us-east-1", "us-west-2"])),
                    created_at=created,
                    updated_at=now,
                    workflow_status=WorkflowStatus(str(rng.choice(["NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"], p=[0.5, 0.2, 0.22, 0.08]))),
                    account_tier=AccountTier.PROD if rng.random() < 0.6 else AccountTier.NON_PROD,
                    is_internet_exposed=bool(rng.random() < 0.2),
                    recurrence_count=int(1 + rng.poisson(1.2)),
                    control_id=str(rng.choice(controls)),
                )
            )
    return out


def _record_row(record: FindingRecord, now: datetime | None = None) -> dict:
    decision = label_finding(record, now)
    return {
        "finding_id": record.finding_id,
        "client_id": record.client_id,
        "title": record.title,
        "severity": record.severity.value,
        "resource_type": record.resource_type,
        "resource_arn": record.resource_arn,
        "region": record.region,
        "control_id": record.control_id or "—",
        "account_tier": record.account_tier.value,
        "internet_exposed": record.is_internet_exposed,
        "recurrence": record.recurrence_count,
        "workflow_status": record.workflow_status.value,
        "created_at": record.created_at,
        "age_days": round(record.age_days(now), 1),
        "urgency": decision.label.value,
        "rule_id": decision.rule_id,
        "rationale": decision.rationale,
    }


@st.cache_data(show_spinner=False, ttl=900)
def load_dataset(path: Path = FINDINGS_PATH, client_ids: tuple[str, ...] | None = None) -> Dataset:
    """Load real anonymised findings if available, else demo data.

    ``scripts/refresh_live_findings.py`` runs on a cron (every 4h) and overwrites ``path`` in
    place; a 15-minute TTL means a running dashboard session picks up a fresh poll within that
    window without needing a manual restart, while still only re-reading the file a few times an
    hour rather than on every rerun.
    """
    records: list[FindingRecord] = []
    if path.exists():
        with path.open(encoding="utf-8") as fh:
            records = [FindingRecord.from_dict(json.loads(line)) for line in fh if line.strip()]
    if not records:
        records = demo_findings_records(list(client_ids) if client_ids else ["demo-client-a", "demo-client-b"])
    frame = pd.DataFrame([_record_row(r) for r in records])
    return Dataset(frame=frame, records=records)


def load_feedback(client_pseudonym: str) -> pd.DataFrame:
    """PR outcomes for one client from DynamoDB; empty frame if unavailable."""
    try:
        import boto3
        from boto3.dynamodb.conditions import Attr

        table = boto3.resource("dynamodb", region_name=os.getenv("AWS_REGION", "ap-south-1")).Table(
            os.getenv("DYNAMODB_FEEDBACK_TABLE", "cspm-remediation-feedback")
        )
        return pd.DataFrame(table.scan(FilterExpression=Attr("client_id").eq(client_pseudonym)).get("Items", []))
    except Exception:  # noqa: BLE001 - dashboard must render without AWS access
        return pd.DataFrame(columns=["outcome"])


# ------------------------------------------------------------- generation history
# Local, file-backed log of every live-generation demo run: survives a page refresh and a
# container restart (bind-mounted via docker-compose's ./data volume), unlike st.session_state
# which only lives for one browser session. This is what lets a past generation be pulled back
# up, and is what the "PR opened" count on the Remediation Pipeline tab actually reflects.
GENERATION_HISTORY_PATH = Path(os.getenv("GENERATION_HISTORY_PATH", "data/generation_history.jsonl"))


def log_generation_event(
    generation_id: str,
    client_pseudonym: str,
    finding_id: str,
    control_id: str,
    title: str,
    severity: str,
    urgency: str,
    hcl: str,
    validation_passed: bool,
    cost_usd: float,
    pr_number: int | None = None,
    pr_url: str | None = None,
    pr_branch: str | None = None,
) -> None:
    """Append one row. Raising a PR later re-logs the same ``generation_id`` with PR fields filled
    in — the reader below keeps only the latest row per id, so this reads as an update."""
    GENERATION_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "generation_id": generation_id,
        "logged_at": datetime.now(timezone.utc).isoformat(),
        "client_id": client_pseudonym,
        "finding_id": finding_id,
        "control_id": control_id,
        "title": title,
        "severity": severity,
        "urgency": urgency,
        "hcl": hcl,
        "validation_passed": validation_passed,
        "cost_usd": cost_usd,
        "pr_number": pr_number,
        "pr_url": pr_url,
        "pr_branch": pr_branch,
    }
    with GENERATION_HISTORY_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")


def load_generation_history(client_pseudonym: str) -> pd.DataFrame:
    """Latest row per generation_id for this client, newest first."""
    empty = pd.DataFrame(columns=["generation_id", "logged_at", "pr_number", "pr_url"])
    if not GENERATION_HISTORY_PATH.exists():
        return empty
    rows = []
    with GENERATION_HISTORY_PATH.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not rows:
        return empty
    frame = pd.DataFrame(rows)
    frame = frame[frame["client_id"] == client_pseudonym]
    if frame.empty:
        return empty
    frame = frame.sort_values("logged_at").drop_duplicates("generation_id", keep="last")
    return frame.sort_values("logged_at", ascending=False)


def _client_labels() -> list[dict[str, str]]:
    """Human-readable names for the configured client account IDs, if known to this deployment."""
    try:
        from scripts.generate_demo_findings import CLIENTS  # type: ignore[import-not-found]

        return CLIENTS
    except Exception:  # noqa: BLE001 - optional, dev-only script may not ship in every deploy
        return []


# ------------------------------------------------------------------ calculations
def compute_posture_score(df: pd.DataFrame) -> float:
    """0-100 posture score: the severity-weighted share of findings that are already closed.

    ``100 * (1 - open_weight / total_weight)`` with weights CRITICAL 10, HIGH 5, MEDIUM 2,
    LOW 0.5. Scale-free (independent of how many findings a client has), 100 when nothing
    is open, and open critical findings pull it down 20x faster than open low ones.
    """
    weights = df["severity"].map(SEVERITY_WEIGHT)
    total = float(weights.sum())
    if total == 0:
        return 100.0
    open_weight = float(weights[~df["workflow_status"].isin(CLOSED)].sum())
    return round(100.0 * (1.0 - open_weight / total), 1)


def fleet_summary(frame: pd.DataFrame, client_ids: list[str], client_names: dict[str, str]) -> pd.DataFrame:
    """One row per configured client: posture score, open findings, open critical."""
    rows = []
    for cid in client_ids:
        pseudonym = hash_account_id(cid)
        sub = frame[frame["client_id"] == pseudonym]
        if sub.empty:
            continue
        open_sub = sub[~sub["workflow_status"].isin(CLOSED)]
        rows.append(
            {
                "account_id": cid,
                "name": client_names.get(cid, cid),
                "posture_score": compute_posture_score(sub),
                "open_findings": len(open_sub),
                "open_critical": int((open_sub["severity"] == "CRITICAL").sum()),
            }
        )
    return pd.DataFrame(rows)


def heatmap_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Open-finding counts: resource type (rows) x severity (columns)."""
    open_findings = df[~df["workflow_status"].isin(CLOSED)]
    matrix = pd.crosstab(open_findings["resource_type"], open_findings["severity"])
    return matrix.reindex(columns=[s for s in SEVERITIES if s in matrix.columns], fill_value=0)


def weekly_trend(df: pd.DataFrame) -> pd.DataFrame:
    """Findings created per week, broken out by severity (for the Overview trend chart)."""
    work = df.copy()
    naive = pd.to_datetime(work["created_at"], utc=True).dt.tz_localize(None)
    work["week"] = naive.dt.to_period("W").dt.start_time
    table = pd.crosstab(work["week"], work["severity"])
    return table.reindex(columns=[s for s in SEVERITIES if s in table.columns], fill_value=0).sort_index()


def pipeline_stages(df: pd.DataFrame, feedback: pd.DataFrame, history: pd.DataFrame | None = None) -> pd.DataFrame:
    """Funnel: ingested -> actionable -> PR opened -> merged.

    "PR opened" comes from the local generation-history log (real, updates live as PRs are
    raised from the demo tab). "PR merged" still comes from the DynamoDB feedback table, which
    is only populated by a GitHub webhook that isn't wired up in this deployment, so it will
    read 0 until that webhook receiver exists.
    """
    merged = int(feedback["outcome"].isin(["accepted", "modified"]).sum()) if "outcome" in feedback else 0
    if history is not None and "pr_number" in history and not history.empty:
        opened = int(history["pr_number"].notna().sum())
    else:
        opened = len(feedback)
    return pd.DataFrame(
        {
            "stage": ["Ingested", "Actionable (not suppressed)", "PR opened", "PR merged"],
            "count": [
                len(df),
                int((df["urgency"] != Urgency.SUPPRESS.value).sum()),
                opened,
                merged,
            ],
        }
    )


def rule_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    """How many findings each labelling rule fired for — transparency into the decision matrix."""
    counts = df["rule_id"].value_counts().rename_axis("rule_id").reset_index(name="count")

    def describe(rule_id: str) -> str:
        base, _, suffix = rule_id.partition("+")
        parts = [RULE_DESCRIPTIONS.get(base, f"base decision matrix cell `{base}`")]
        if suffix:
            parts.append(RULE_DESCRIPTIONS.get(suffix, suffix))
        return "; ".join(parts)

    counts["description"] = counts["rule_id"].map(describe)
    return counts.sort_values("count", ascending=False)


def binary_status() -> dict[str, bool]:
    """Whether each external validation/LLM tool this project depends on is reachable."""
    return {
        "terraform": shutil.which(os.getenv("TERRAFORM_BIN", "terraform")) is not None,
        "tflint": shutil.which(os.getenv("TFLINT_BIN", "tflint")) is not None,
        "opa": shutil.which(os.getenv("OPA_BIN", "opa")) is not None,
    }


# --------------------------------------------------------------------- figures
def build_heatmap(matrix: pd.DataFrame) -> go.Figure:
    fig = go.Figure(
        go.Heatmap(
            z=matrix.values, x=list(matrix.columns), y=list(matrix.index),
            colorscale=BLUE_SCALE, xgap=2, ygap=2, texttemplate="%{z}",
            colorbar={"title": "Open findings"},
            hovertemplate="%{y} / %{x}: %{z} open<extra></extra>",
        )
    )
    fig.update_layout(
        margin={"t": 24, "r": 8, "b": 8, "l": 8}, yaxis={"autorange": "reversed"}, height=380,
        paper_bgcolor=SURFACE, plot_bgcolor=SURFACE, font=CHART_FONT,
    )
    return fig


def build_trend_chart(trend: pd.DataFrame) -> go.Figure:
    fig = go.Figure()
    for severity in trend.columns:
        fig.add_bar(
            x=trend.index, y=trend[severity], name=severity, marker_color=SEVERITY_COLOUR[severity],
            marker_cornerradius=3,
            hovertemplate=f"{severity}<br>week of %{{x|%b %d}}: %{{y}}<extra></extra>",
        )
    fig.update_layout(
        barmode="stack", bargap=0.15,
        title={"text": "New findings per week, by severity", "x": 0, "font": {"size": 14, "color": INK}},
        paper_bgcolor=SURFACE, plot_bgcolor=SURFACE, font=CHART_FONT,
        xaxis={"title": None, "gridcolor": GRID, "linecolor": BASELINE_AXIS},
        yaxis={"title": "Findings", "gridcolor": GRID, "zeroline": False},
        legend={"orientation": "h", "y": 1.18, "x": 0},
        margin={"t": 70, "r": 16, "b": 24, "l": 48}, height=320,
    )
    return fig


def build_pipeline_chart(stages: pd.DataFrame) -> go.Figure:
    fig = go.Figure(
        go.Bar(
            x=stages["count"], y=stages["stage"], orientation="h", marker_color=STAGE_COLOURS,
            marker_cornerradius=4, text=stages["count"], textposition="outside",
            hovertemplate="%{y}: %{x}<extra></extra>",
        )
    )
    fig.update_layout(margin={"t": 24, "r": 32, "b": 8, "l": 8}, yaxis={"autorange": "reversed"},
                      xaxis={"title": "Findings"}, height=260, showlegend=False,
                      paper_bgcolor=SURFACE, plot_bgcolor=SURFACE, font=CHART_FONT)
    return fig


def build_urgency_chart(df: pd.DataFrame) -> go.Figure:
    order = [u.value for u in URGENCY_ORDER][::-1]
    counts = df["urgency"].value_counts().reindex(order, fill_value=0)
    fig = go.Figure(
        go.Bar(
            x=counts.values, y=counts.index, orientation="h",
            marker_color=[URGENCY_COLOUR[u] for u in counts.index], marker_cornerradius=4,
            text=counts.values, textposition="outside",
            hovertemplate="%{y}: %{x}<extra></extra>",
        )
    )
    fig.update_layout(margin={"t": 8, "r": 32, "b": 8, "l": 8}, xaxis={"title": "Findings"},
                      height=220, showlegend=False, paper_bgcolor=SURFACE, plot_bgcolor=SURFACE, font=CHART_FONT)
    return fig


def build_shap_chart(features: list[str], importance: list[float]) -> go.Figure:
    order = np.argsort(importance)
    fig = go.Figure(
        go.Bar(
            x=np.array(importance)[order], y=np.array(features)[order], orientation="h",
            marker_color=BLUE_SOLID, marker_cornerradius=4,
            hovertemplate="%{y}: %{x:.3f}<extra></extra>",
        )
    )
    fig.update_layout(margin={"t": 8, "r": 16, "b": 8, "l": 8}, xaxis={"title": "mean |SHAP value|"},
                      height=260, showlegend=False, paper_bgcolor=SURFACE, plot_bgcolor=SURFACE, font=CHART_FONT)
    return fig


def build_fleet_bar(fleet: pd.DataFrame, column: str, colour: str, title: str) -> go.Figure:
    ordered = fleet.sort_values(column)
    fig = go.Figure(
        go.Bar(
            x=ordered[column], y=ordered["name"], orientation="h", marker_color=colour,
            marker_cornerradius=4, text=ordered[column], textposition="outside",
            hovertemplate="%{y}: %{x}<extra></extra>",
        )
    )
    fig.update_layout(
        title={"text": title, "x": 0, "font": {"size": 13, "color": INK}},
        margin={"t": 36, "r": 32, "b": 8, "l": 8}, height=180 + 36 * len(fleet),
        showlegend=False, paper_bgcolor=SURFACE, plot_bgcolor=SURFACE, font=CHART_FONT,
    )
    return fig


# --------------------------------------------------------------- live AI demo
@st.cache_resource(show_spinner=False)
def get_retriever():
    """A ChromaDB retriever built once per container lifetime (offline hashing embedder: fast,
    deterministic, no model download — fine for this project's five-to-a-dozen reference modules).
    """
    from rag_pipeline.module_indexer import HashingEmbedder, index_modules
    from rag_pipeline.retriever import ModuleRetriever

    embedder = HashingEmbedder()
    chroma_dir = Path(tempfile.gettempdir()) / "cspm_dashboard_chroma"
    index_modules(os.getenv("TERRAFORM_MODULES_DIR", "terraform_modules"), chroma_dir, embedder)
    return ModuleRetriever(chroma_path=str(chroma_dir), embedder=embedder)


def run_live_generation(finding: FindingRecord, prediction) -> dict:
    """classify (already done) -> retrieve -> prompt -> real Bedrock call -> validate.

    This is the only place in the dashboard that spends real money -- every caller must check
    ``MAX_LIVE_GENERATIONS_PER_SESSION`` before invoking it.
    """
    from rag_pipeline.bedrock_client import BedrockClient, BedrockGenerationError
    from rag_pipeline.prompt_builder import build_manual_advisory, build_prompt, requires_manual_remediation
    from rag_pipeline.validator import summarise, validate_hcl

    modules = get_retriever().retrieve(finding, k=3)
    if requires_manual_remediation(modules):
        return {"advisory": build_manual_advisory(finding), "modules": []}

    bundle = build_prompt(finding, modules, prediction)
    try:
        result = BedrockClient().generate(bundle.system, bundle.user)
    except BedrockGenerationError as exc:
        return {"error": str(exc), "modules": modules}

    out = {"modules": modules, "bundle": bundle, "result": result}
    if not result.declined:
        validation = validate_hcl(result.hcl)
        out["validation"] = validation
        out["validation_summary"] = summarise(validation)
    return out


# --------------------------------------------------------------------------- UI
def _style_severity(frame: pd.DataFrame):
    """Pandas Styler: colour-code the severity column using the reserved status palette."""

    def colour(value: object) -> str:
        hex_colour = SEVERITY_COLOUR.get(str(value), MUTED)
        return f"background-color: {hex_colour}22; color: {INK}; font-weight: 600;"

    return frame.style.map(colour, subset=["severity"])


def render_header() -> None:
    st.markdown(
        f"""
        <style>
        [data-testid="stMetricValue"] {{ font-size: 1.5rem; }}
        [data-testid="stMetric"] {{
            background: #ffffff; border: 1px solid {GRID}; border-radius: 10px;
            padding: 10px 14px; box-shadow: 0 1px 2px rgba(11,11,11,0.05);
        }}
        .cspm-header {{
            padding: 1.3rem 1.6rem; border-radius: 14px; margin-bottom: 1.1rem;
            background: linear-gradient(135deg, #0d366b 0%, #2a78d6 55%, #3987e5 100%);
            color: #ffffff;
        }}
        .cspm-badge {{
            display: inline-block; background: rgba(255,255,255,0.18);
            padding: 3px 12px; border-radius: 999px; font-size: 0.72rem;
            letter-spacing: 0.08em; font-weight: 700; margin-bottom: 8px;
        }}
        .cspm-title {{ font-size: 1.3rem; line-height: 1.4; font-weight: 700; margin: 0; max-width: 62rem; }}
        .cspm-tagline {{ font-size: 0.86rem; opacity: 0.92; margin-top: 8px; }}
        </style>
        <div class="cspm-header">
            <span class="cspm-badge">\U0001F6E1️ {PROJECT_BADGE}</span>
            <p class="cspm-title">{PROJECT_TITLE_FULL}</p>
            <p class="cspm-tagline">{TAGLINE}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_fleet_tab(dataset: Dataset, clients: list[str], client_names: dict[str, str]) -> None:
    fleet = fleet_summary(dataset.frame, clients, client_names)
    if fleet.empty:
        st.info("No data yet for any configured client.")
        return
    f1, f2, f3 = st.columns(3)
    f1.metric("Accounts monitored", len(fleet))
    f2.metric("Fleet-wide open findings", int(fleet["open_findings"].sum()))
    f3.metric("Fleet-wide open critical", int(fleet["open_critical"].sum()),
              delta=None if fleet["open_critical"].sum() == 0 else "needs attention", delta_color="inverse")
    c1, c2 = st.columns(2)
    with c1:
        st.plotly_chart(build_fleet_bar(fleet, "posture_score", BLUE_SOLID, "Posture score by account (0-100)"), width="stretch")
    with c2:
        st.plotly_chart(build_fleet_bar(fleet, "open_findings", ORANGE_SOLID, "Open findings by account"), width="stretch")
    st.dataframe(fleet.rename(columns={"account_id": "AWS Account", "name": "Account", "posture_score": "Posture",
                                       "open_findings": "Open", "open_critical": "Open critical"}),
                hide_index=True, width="stretch")


def render_demo_tab(dataset: Dataset, df: pd.DataFrame, pseudonym: str) -> None:
    st.markdown("#### Live remediation generation")
    st.caption(
        "Runs the *real* pipeline on a finding you pick: retrieve a matching Terraform module from "
        "ChromaDB, prompt Claude Sonnet 5 on Amazon Bedrock, then validate the result with "
        "`terraform validate` → `tflint` → OPA — the same chain used in production. Each click is a "
        "real, billed API call (~$0.01-0.03)."
    )
    st.session_state.setdefault("live_gen_count", 0)
    st.session_state.setdefault("live_gen_cost", 0.0)

    actionable = df[df["urgency"] != Urgency.SUPPRESS.value]
    if actionable.empty:
        st.warning("No actionable findings for this client under the current filters.")
    else:
        options = actionable.sort_values("age_days", ascending=False)["finding_id"].tolist()
        label_by_id = {r["finding_id"]: f"{r['control_id']} — {r['title']} ({r['severity']})"
                      for r in actionable.to_dict("records")}
        chosen = st.selectbox("Pick a finding to remediate", options, format_func=lambda fid: label_by_id[fid])

        remaining = MAX_LIVE_GENERATIONS_PER_SESSION - st.session_state["live_gen_count"]
        st.caption(f"Live generations this session: {st.session_state['live_gen_count']}/{MAX_LIVE_GENERATIONS_PER_SESSION} "
                  f"(~${st.session_state['live_gen_cost']:.4f} spent so far)")

        if st.button("✨ Generate remediation now", disabled=remaining <= 0, type="primary"):
            record = next(r for r in dataset.records if r.finding_id == chosen)
            from classifier.predict import UrgencyClassifier

            prediction = UrgencyClassifier(model=_load_model_cached()).classify(record)
            with st.spinner("Retrieving modules, calling Claude Sonnet 5, validating output..."):
                outcome = run_live_generation(record, prediction)

            if "error" in outcome:
                st.session_state["demo_outcome"] = None
                st.error(f"Bedrock call failed: {outcome['error']}")
            elif "advisory" in outcome:
                st.session_state["demo_outcome"] = None
                st.warning("No matching Terraform module was retrieved — graceful degradation kicked in.")
                st.info(outcome["advisory"])
            else:
                st.session_state["live_gen_count"] += 1
                st.session_state["live_gen_cost"] += outcome["result"].estimated_cost_usd
                # Persist across reruns (e.g. scrolling over a sidebar widget) — a local variable
                # here only survives the single script run triggered by this click.
                st.session_state["demo_outcome"] = outcome
                st.session_state["demo_record"] = record
                st.session_state["demo_prediction"] = prediction
                st.session_state["demo_pr_result"] = None
                st.session_state["demo_generation_id"] = uuid.uuid4().hex[:12]
                if not outcome["result"].declined:
                    log_generation_event(
                        generation_id=st.session_state["demo_generation_id"],
                        client_pseudonym=pseudonym,
                        finding_id=record.finding_id,
                        control_id=record.control_id or "",
                        title=record.title,
                        severity=record.severity.value,
                        urgency=prediction.label.value,
                        hcl=outcome["result"].hcl,
                        validation_passed=outcome["validation"].passed,
                        cost_usd=outcome["result"].estimated_cost_usd,
                    )

        outcome = st.session_state.get("demo_outcome")
        if outcome is not None:
            result = outcome["result"]

            st.markdown("**Modules retrieved from ChromaDB**")
            st.dataframe(
                pd.DataFrame([{"module": m.name, "score": round(m.score, 2),
                               "resource_type_match": m.resource_type_match,
                               "control_match": m.control_match} for m in outcome["modules"]]),
                hide_index=True, width="stretch",
            )

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Input tokens", result.input_tokens)
            m2.metric("Output tokens", result.output_tokens)
            m3.metric("Thinking tokens", result.thinking_tokens)
            m4.metric("Est. cost", f"${result.estimated_cost_usd:.4f}")

            if result.declined:
                st.warning("The model declined to generate remediation for this finding (NO_SAFE_REMEDIATION).")
            else:
                st.markdown("**Generated Terraform**")
                st.code(result.hcl, language="hcl")
                st.caption(
                    "Copy icon needs a secure (HTTPS) origin to work in most browsers — this site is "
                    "still plain HTTP, so select the code and use Ctrl+C / Cmd+C if the icon doesn't respond."
                )
                st.markdown("**Validation (`terraform validate` → `tflint` → OPA)**")
                for stage in outcome["validation"].stages:
                    icon = "⏭️" if stage.skipped else ("✅" if stage.passed else "❌")
                    st.markdown(f"{icon} **{stage.name}**" + (f" — {'; '.join(stage.errors)}" if stage.errors else ""))

                pr_result = st.session_state.get("demo_pr_result")
                if pr_result is not None:
                    verb = "Opened" if pr_result.created else "Already open"
                    st.success(f"{verb}: [PR #{pr_result.number}]({pr_result.url}) — `{pr_result.branch}`")
                elif outcome["validation"].passed:
                    if st.button("🚀 Raise PR", type="primary"):
                        try:
                            from approval_workflow.github_pr import GitHubPRClient

                            client = GitHubPRClient()
                            record = st.session_state["demo_record"]
                            prediction = st.session_state["demo_prediction"]
                            pr = client.create_remediation_pr(
                                record,
                                result.hcl,
                                prediction=prediction,
                                validation=outcome["validation"],
                                bundle=outcome.get("bundle"),
                            )
                            st.session_state["demo_pr_result"] = pr
                            log_generation_event(
                                generation_id=st.session_state["demo_generation_id"],
                                client_pseudonym=pseudonym,
                                finding_id=record.finding_id,
                                control_id=record.control_id or "",
                                title=record.title,
                                severity=record.severity.value,
                                urgency=prediction.label.value,
                                hcl=result.hcl,
                                validation_passed=outcome["validation"].passed,
                                cost_usd=result.estimated_cost_usd,
                                pr_number=pr.number,
                                pr_url=pr.url,
                                pr_branch=pr.branch,
                            )
                            st.rerun()
                        except Exception as exc:  # noqa: BLE001 - surface any GitHub/auth error to the user
                            st.error(f"Could not open the PR: {exc}")
                else:
                    st.info("Validation did not pass, so this result is not eligible to become a PR.")

    st.divider()
    st.markdown("#### Past generations")
    st.caption(
        "Survives a page refresh and container restart — stored on disk, not in the browser session. "
        "Expand a row to see the exact Terraform that was generated, and pull it back up if you need it again."
    )
    history = load_generation_history(pseudonym)
    if history.empty:
        st.caption("Nothing generated yet for this client.")
    else:
        for _, row in history.iterrows():
            pr_label = f"PR #{int(row['pr_number'])}" if pd.notna(row.get("pr_number")) else "no PR"
            status = "✅" if row.get("validation_passed") else "❌"
            when = row["logged_at"][:16].replace("T", " ") if row.get("logged_at") else "?"
            with st.expander(f"{status} {when} UTC — {row.get('control_id') or row.get('title')} — {pr_label}"):
                st.caption(f"{row.get('title', '')} · {row.get('severity', '')} · urgency {row.get('urgency', '')} "
                          f"· ${float(row.get('cost_usd') or 0):.4f}")
                if pd.notna(row.get("pr_number")):
                    st.markdown(f"[PR #{int(row['pr_number'])}]({row['pr_url']}) — `{row['pr_branch']}`")
                st.code(row.get("hcl", ""), language="hcl")

    st.divider()
    st.markdown("#### Test the safety guardrail (free — no Bedrock call)")
    st.caption(
        "`opa_policies/terraform_safety.rego` rejects world-open ingress, wildcard IAM and "
        "`force_destroy`. Paste or edit Terraform below and check it against the real policy."
    )
    hcl_text = st.text_area("Terraform to check", value=SAMPLE_DANGEROUS_HCL, height=220)
    if st.button("Check against OPA policy"):
        from rag_pipeline.validator import run_opa

        opa_result = run_opa(hcl_text)
        if opa_result.passed:
            st.success("PASS — no safety violations found.")
        else:
            st.error("FAIL — the following violations were found:")
            for err in opa_result.errors:
                st.markdown(f"- {err}")


def render_module_library_tab() -> None:
    from rag_pipeline.module_indexer import discover_modules

    try:
        modules = discover_modules(os.getenv("TERRAFORM_MODULES_DIR", "terraform_modules"))
    except Exception as exc:  # noqa: BLE001
        st.error(f"Could not load the module library: {exc}")
        return

    st.caption(f"{len(modules)} reviewed, deployable Terraform modules back the RAG retriever.")
    overview = pd.DataFrame(
        [{"module": m.name, "controls": ", ".join(m.controls), "resource_types": ", ".join(m.resource_types),
          "description": m.description} for m in modules]
    )
    st.dataframe(overview, hide_index=True, width="stretch")

    for module in modules:
        with st.expander(f"\U0001F4C4 {module.name}"):
            st.markdown(f"**Controls:** {', '.join(module.controls) or '—'}  \n**Resource types:** {', '.join(module.resource_types) or '—'}")
            st.code(module.hcl, language="hcl")


def _load_model_cached():
    try:
        from classifier.predict import load_registered_model

        return load_registered_model()
    except Exception:  # noqa: BLE001 - no model registered yet is the common case
        return None


@st.cache_data(show_spinner="Computing SHAP importance...")
def _shap_chart_for(_model, client_ids: tuple[str, ...]) -> go.Figure:
    """Cached on (model identity via leading underscore, selected client ids) — this only ever
    depends on which client(s) are selected, not on the severity/status/age sidebar filters, so
    that's the whole cache key. Without caching, this re-ran SHAP over every record for the
    client on *every* Streamlit rerun (any button anywhere in the app), which was fine at 135
    synthetic rows and became the dashboard's main slowdown once a client had 12,647 real rows.
    """
    from classifier.evaluate import shap_values_for
    from classifier.feature_engineering import FEATURE_COLUMNS, build_feature_frame

    dataset = load_dataset()
    records = [r for r in dataset.records if r.client_id in set(client_ids)]
    features = build_feature_frame(records)
    values = shap_values_for(_model, features)
    importance = np.abs(values).mean(axis=(0, 2))
    return build_shap_chart(FEATURE_COLUMNS, list(importance))


def main() -> None:  # pragma: no cover - exercised via `streamlit run`
    st.set_page_config(page_title=PROJECT_BADGE, page_icon="\U0001F6E1️", layout="wide")
    render_header()

    configured = [c.strip() for c in os.getenv("CLIENT_ACCOUNT_IDS", "").split(",") if c.strip()]
    clients = configured or ["demo-client-a", "demo-client-b"]
    client_names = {c["account_id"]: c["name"] for c in _client_labels()}
    dataset = load_dataset(client_ids=tuple(clients))

    with st.sidebar:
        st.header("Filters")
        client = st.selectbox(
            "Client account", clients,
            format_func=lambda c: f"{client_names.get(c, c)} ({c})" if c in client_names else c,
        )
        if not configured:
            st.caption("CLIENT_ACCOUNT_IDS not set — showing demo clients.")

        pseudonym = hash_account_id(client)
        df_all = dataset.frame[dataset.frame["client_id"] == pseudonym]

        severities = st.multiselect("Severity", SEVERITIES, default=SEVERITIES)
        statuses = st.multiselect(
            "Workflow status", sorted(df_all["workflow_status"].unique()) if not df_all.empty else [],
            default=sorted(df_all["workflow_status"].unique()) if not df_all.empty else [],
        )
        min_age = int(df_all["age_days"].max()) if not df_all.empty else 0
        age_range = st.slider("Finding age (days)", 0, max(min_age, 1), (0, max(min_age, 1)))
        st.divider()
        st.caption(f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}")

    tab_fleet, tab_overview, tab_findings, tab_classifier, tab_demo, tab_modules, tab_pipeline, tab_system = st.tabs(
        ["\U0001F3E2 Fleet Overview", "\U0001F4CA Client Overview", "\U0001F50D Findings Explorer",
         "\U0001F9E0 Classifier Insights", "\U0001F916 AI Remediation Demo", "\U0001F4DA Module Library",
         "\U0001F501 Remediation Pipeline", "⚙️ System Status"]
    )

    with tab_fleet:
        render_fleet_tab(dataset, clients, client_names)

    if df_all.empty:
        with tab_overview:
            st.info("No findings for this client yet.")
        return

    df = df_all[
        df_all["severity"].isin(severities)
        & df_all["workflow_status"].isin(statuses)
        & df_all["age_days"].between(*age_range)
    ]
    if df.empty:
        with tab_overview:
            st.warning("No findings match the current filters.")
        return

    open_count = int((~df["workflow_status"].isin(CLOSED)).sum())
    critical_open = int(((df["severity"] == "CRITICAL") & ~df["workflow_status"].isin(CLOSED)).sum())
    mean_age_open = df.loc[~df["workflow_status"].isin(CLOSED), "age_days"].mean()
    exposed_open = int((df["internet_exposed"] & ~df["workflow_status"].isin(CLOSED)).sum())

    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Posture score", f"{compute_posture_score(df):.0f} / 100")
    k2.metric("Open findings", open_count)
    k3.metric("Open critical", critical_open, delta=None if critical_open == 0 else f"{critical_open} need attention", delta_color="inverse")
    k4.metric("Mean age (open)", f"{mean_age_open:.0f}d" if open_count else "—")
    k5.metric("Internet-exposed (open)", exposed_open)

    with tab_overview:
        c1, c2 = st.columns([3, 2])
        with c1:
            st.markdown("**Open findings — resource type × severity**")
            st.plotly_chart(build_heatmap(heatmap_matrix(df)), width="stretch")
        with c2:
            st.markdown("**Urgency classification**")
            st.plotly_chart(build_urgency_chart(df), width="stretch")
        st.plotly_chart(build_trend_chart(weekly_trend(df)), width="stretch")

    with tab_findings:
        st.caption(f"{len(df)} findings match the current filters.")
        display_cols = ["finding_id", "severity", "control_id", "resource_type", "account_tier",
                        "workflow_status", "urgency", "age_days", "recurrence", "internet_exposed"]
        st.dataframe(_style_severity(df[display_cols].sort_values("age_days", ascending=False)), width="stretch", height=420)
        st.download_button(
            "⬇️ Export filtered findings (CSV)",
            df[display_cols].to_csv(index=False).encode("utf-8"),
            file_name=f"cspm_findings_{client}.csv", mime="text/csv",
        )

    with tab_classifier:
        st.markdown("**Why findings are labelled the way they are**")
        model = _load_model_cached()
        if model is not None:
            st.success("Registered XGBoost model loaded from the MLflow registry — classifications use it.")
            client_ids = tuple(sorted(df["client_id"].unique()))
            st.plotly_chart(_shap_chart_for(model, client_ids), width="stretch")
        else:
            st.info(
                "No model is registered in MLflow yet, so every finding falls back to the rule-based "
                "labeller (`classifier/labeller.py`). Breakdown of which rule fired for each finding:"
            )
            st.dataframe(rule_breakdown(df), hide_index=True, width="stretch")

    with tab_demo:
        render_demo_tab(dataset, df, pseudonym)

    with tab_modules:
        render_module_library_tab()

    with tab_pipeline:
        st.markdown("**Remediation funnel**")
        feedback = load_feedback(pseudonym)
        history = load_generation_history(pseudonym)
        stages = pipeline_stages(df, feedback, history)
        st.plotly_chart(build_pipeline_chart(stages), width="stretch")

        opened = history[history["pr_number"].notna()] if "pr_number" in history and not history.empty else history
        if not opened.empty:
            st.markdown("**Recently opened PRs**")
            st.dataframe(
                opened[["logged_at", "control_id", "severity", "urgency", "pr_number", "pr_url"]]
                .rename(columns={"logged_at": "Opened (UTC)", "control_id": "Control", "severity": "Severity",
                                 "urgency": "Urgency", "pr_number": "PR #", "pr_url": "URL"}),
                hide_index=True, width="stretch",
            )
        if "outcome" in feedback.columns and not feedback.empty:
            st.markdown("**Recent PR outcomes (merged/closed)**")
            st.dataframe(feedback, width="stretch")
        elif opened.empty:
            st.caption("No PRs raised yet from the AI Remediation Demo tab for this client.")
        else:
            st.caption(
                "No merge/close outcomes recorded yet in DynamoDB — that side needs a GitHub webhook "
                "receiver wired up, which this deployment doesn't have (see System Status). PR-opened "
                "counts above come from this app directly and don't depend on it."
            )

    with tab_system:
        st.markdown("**Configuration & tooling**")
        checks = {
            "Embedder": os.getenv("EMBEDDER", "default"),
            "Bedrock model": os.getenv("BEDROCK_MODEL_ID", "not set"),
            "Bedrock effort": os.getenv("BEDROCK_EFFORT", "low"),
            "MLflow tracking URI": os.getenv("MLFLOW_TRACKING_URI", "not set"),
            "GitHub repo configured": bool(os.getenv("GITHUB_REPO")),
            "Slack webhook configured": bool(os.getenv("SLACK_WEBHOOK_URL")),
            "Terraform modules available": sum(
                1 for p in Path(os.getenv("TERRAFORM_MODULES_DIR", "terraform_modules")).glob("*/main.tf")
            ) if Path(os.getenv("TERRAFORM_MODULES_DIR", "terraform_modules")).exists() else 0,
        }
        checks.update({f"`{tool}` on PATH": ok for tool, ok in binary_status().items()})
        st.table(pd.Series(checks, name="value").astype(str))


if __name__ == "__main__":
    main()
