"""Mean time-to-remediate: baseline vs. post-system, with a significance test and a chart."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.graph_objects as go
from scipy import stats

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Reference categorical slots 1 (blue) and 2 (orange) - a validated adjacent pair.
BASELINE_COLOUR = "#2a78d6"
SYSTEM_COLOUR = "#eb6834"
SURFACE, INK, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#898781", "#e1e0d9"


def load_snapshots(source: str | Path) -> pd.DataFrame:
    """Load one CSV, or every ``*.csv`` under a directory (recursively), into one frame."""
    source = Path(source)
    paths = sorted(source.rglob("*.csv")) if source.is_dir() else [source]
    if not paths:
        raise FileNotFoundError(f"No CSV files found under {source}")
    return pd.concat([pd.read_csv(p) for p in paths], ignore_index=True)


def compute_ttr(snapshots: pd.DataFrame) -> pd.DataFrame:
    """Per-finding time-to-remediate in hours.

    ``created_at`` is the earliest value seen; ``resolved_at`` is the earliest ``updated_at``
    among rows where the finding is RESOLVED. Findings never seen as resolved are excluded.
    """
    df = snapshots.copy()
    for col in ("created_at", "updated_at"):
        df[col] = pd.to_datetime(df[col], utc=True)
    created = df.groupby("finding_id")["created_at"].min()
    resolved = df[df["workflow_status"] == "RESOLVED"].groupby("finding_id")["updated_at"].min()
    severity = df.sort_values("updated_at").groupby("finding_id")["severity"].last()

    out = pd.concat({"created_at": created, "resolved_at": resolved, "severity": severity}, axis=1).dropna(
        subset=["resolved_at"]
    )
    out["ttr_hours"] = (out["resolved_at"] - out["created_at"]).dt.total_seconds() / 3600.0
    return out[out["ttr_hours"] >= 0]


def summarise_mttr(ttr: pd.DataFrame) -> pd.DataFrame:
    """Count / mean / median TTR (hours) per severity, plus an ALL row."""
    by_sev = ttr.groupby("severity")["ttr_hours"].agg(n="count", mean_hours="mean", median_hours="median")
    overall = pd.DataFrame(
        {"n": [len(ttr)], "mean_hours": [ttr["ttr_hours"].mean()], "median_hours": [ttr["ttr_hours"].median()]},
        index=["ALL"],
    )
    ordered = [s for s in SEVERITY_ORDER if s in by_sev.index]
    return pd.concat([by_sev.loc[ordered], overall])


def compare(baseline_ttr: pd.DataFrame, post_ttr: pd.DataFrame) -> dict[str, Any]:
    """MTTR delta and a one-sided Mann-Whitney U test (H1: post-system TTR is lower)."""
    base, post = summarise_mttr(baseline_ttr), summarise_mttr(post_ttr)
    table = base.join(post, lsuffix="_baseline", rsuffix="_post", how="outer")
    table = table.reindex([s for s in SEVERITY_ORDER + ["ALL"] if s in table.index])
    table["delta_hours"] = table["mean_hours_post"] - table["mean_hours_baseline"]
    table["pct_change"] = 100.0 * table["delta_hours"] / table["mean_hours_baseline"]

    u_stat, p_value = stats.mannwhitneyu(
        post_ttr["ttr_hours"], baseline_ttr["ttr_hours"], alternative="less"
    )
    return {"table": table, "u_statistic": float(u_stat), "p_value": float(p_value),
            "significant_at_0_05": bool(p_value < 0.05)}


def plot_comparison(baseline: pd.DataFrame, post: pd.DataFrame, out_html: str | Path | None = None) -> go.Figure:
    """Grouped bars of mean TTR per severity: baseline vs. with-system (one axis, hours)."""
    sevs = [s for s in SEVERITY_ORDER + ["ALL"] if s in baseline.index and s in post.index]
    fig = go.Figure()
    for name, frame, colour in (("Baseline", baseline, BASELINE_COLOUR), ("With system", post, SYSTEM_COLOUR)):
        values = [float(frame.loc[s, "mean_hours"]) for s in sevs]
        fig.add_bar(
            x=sevs, y=values, name=name, marker_color=colour, marker_cornerradius=4,
            text=[f"{v:,.1f}" for v in values], textposition="outside",
            textfont={"color": INK, "size": 12},
            hovertemplate=f"{name}<br>%{{x}}: %{{y:,.1f}} h<extra></extra>",
        )
    fig.update_layout(
        title={"text": "Mean time to remediate, before vs. after", "x": 0, "font": {"size": 16, "color": INK}},
        barmode="group", bargap=0.35, bargroupgap=0.08,
        paper_bgcolor=SURFACE, plot_bgcolor=SURFACE,
        font={"family": "system-ui, -apple-system, 'Segoe UI', sans-serif", "color": MUTED},
        yaxis={"title": "Mean TTR (hours)", "gridcolor": GRID, "zeroline": False},
        xaxis={"title": "Severity", "linecolor": GRID},
        legend={"orientation": "h", "y": 1.12, "x": 0},
        margin={"t": 90, "r": 24, "b": 56, "l": 64},
    )
    if out_html:
        Path(out_html).parent.mkdir(parents=True, exist_ok=True)
        fig.write_html(str(out_html), include_plotlyjs="cdn")
    return fig


def main() -> None:  # pragma: no cover - thin CLI
    parser = argparse.ArgumentParser(description="Compare baseline vs post-system MTTR")
    parser.add_argument("--baseline", required=True, help="baseline CSV file or directory of snapshots")
    parser.add_argument("--post", required=True, help="post-system CSV file or directory of snapshots")
    parser.add_argument("--out", default="artifacts/mttr_comparison.html")
    args = parser.parse_args()

    baseline_ttr = compute_ttr(load_snapshots(args.baseline))
    post_ttr = compute_ttr(load_snapshots(args.post))
    result = compare(baseline_ttr, post_ttr)
    print(result["table"].round(2).to_string())
    print(f"Mann-Whitney U={result['u_statistic']:.1f}, one-sided p={result['p_value']:.4g}")
    plot_comparison(summarise_mttr(baseline_ttr), summarise_mttr(post_ttr), args.out)
    print(f"Chart written to {args.out}")


if __name__ == "__main__":  # pragma: no cover
    main()
