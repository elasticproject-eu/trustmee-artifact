#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError as exc:
    raise SystemExit(
        "matplotlib and numpy are required to generate figures. "
        "Install them in your environment."
    ) from exc


DEFAULT_FIGWIDTH = 3.35
DEFAULT_EVAL_WIDE = 6.8
PAPER_FIGWIDTH = 4
PAPER_FIGHEIGHT = 3
PAPER_SUBPLOT = {"left": 0.18, "right": 0.94, "top": 0.96, "bottom": 0.16}
PAPER_HEADROOM_RATIO = 0.28
PAPER_NATIVE_LABEL = "native"
PAPER_WASM_LABEL = "Wasm-based"
PAPER_TEE_LABELS = {"snp": "SEV-SNP", "tdx": "TDX"}
PAPER_NATIVE_COLOR = "#81c784"
PAPER_WASM_COLOR = "#63b5f6"
NUMERIC_LABEL_DELTA = 1


@dataclass(frozen=True)
class LatencySeries:
    e2e_mean: np.ndarray
    e2e_std: np.ndarray
    ver_mean: np.ndarray
    ver_std: np.ndarray


@dataclass(frozen=True)
class ResourceSeries:
    rss_mean: np.ndarray
    rss_std: np.ndarray
    cpu_mean: np.ndarray
    cpu_std: np.ndarray


@dataclass(frozen=True)
class BreakdownSeries:
    labels: list[str]
    native_mean: np.ndarray
    native_std: np.ndarray
    wasm_mean: np.ndarray
    wasm_std: np.ndarray


def paper_tee_label(platform: str) -> str:
    return PAPER_TEE_LABELS.get(platform.lower(), platform.upper())


def paper_bar_labels(primary_labels: list[str]) -> list[str]:
    labels = []
    for primary in primary_labels:
        labels.append(f"{primary}\n{PAPER_NATIVE_LABEL}")
        labels.append(f"{primary}\n{PAPER_WASM_LABEL}")
    return labels


def paper_bar_colors(group_count: int) -> list[str]:
    return [PAPER_NATIVE_COLOR, PAPER_WASM_COLOR] * group_count


def paper_dense_tick_labelsize(multiline: bool = False) -> float:
    base = plt.rcParams["font.size"]
    drop = 3.2 if not multiline else 1
    return max(base - drop, 6.0)


def paper_dense_value_fontsize(stacked: bool = False) -> float:
    base = plt.rcParams["font.size"]
    drop = 2 if not stacked else 2.6
    return max(base - drop + NUMERIC_LABEL_DELTA, 5.6)


def read_json(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"missing results file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_latency(path: Path) -> tuple[float, float]:
    data = read_json(path)
    return float(data.get("mean_ms", 0.0)), float(data.get("std_ms", 0.0))


def load_verifier_time(path: Path) -> tuple[float, float]:
    data = read_json(path)
    ms = data.get("ms", {})
    return float(ms.get("mean", 0.0)), float(ms.get("std", 0.0))


def load_mean_std(data: dict, key: str) -> tuple[float, float]:
    item = data.get(key, {})
    return float(item.get("mean", 0.0)), float(item.get("std", 0.0))


def load_platform(results_dir: Path, platform: str) -> LatencySeries:
    prefix = platform.lower()
    e2e_native = load_latency(results_dir / f"{prefix}_native_latency.json")
    e2e_wasm = load_latency(results_dir / f"{prefix}_wasm_latency.json")
    ver_native = load_verifier_time(results_dir / f"{prefix}_native_verifier_time.json")
    ver_wasm = load_verifier_time(results_dir / f"{prefix}_wasm_verifier_time.json")
    return LatencySeries(
        e2e_mean=np.array([e2e_native[0], e2e_wasm[0]], dtype=float),
        e2e_std=np.array([e2e_native[1], e2e_wasm[1]], dtype=float),
        ver_mean=np.array([ver_native[0], ver_wasm[0]], dtype=float),
        ver_std=np.array([ver_native[1], ver_wasm[1]], dtype=float),
    )


def load_latency_pair(results_dir: Path, prefix: str, suffix: str) -> tuple[np.ndarray, np.ndarray]:
    native = load_latency(results_dir / f"{prefix}_native_{suffix}.json")
    wasm = load_latency(results_dir / f"{prefix}_wasm_{suffix}.json")
    mean = np.array([native[0], wasm[0]], dtype=float)
    std = np.array([native[1], wasm[1]], dtype=float)
    return mean, std


def load_verifier_pair(results_dir: Path, prefix: str) -> tuple[np.ndarray, np.ndarray]:
    native = load_verifier_time(results_dir / f"{prefix}_native_verifier_time.json")
    wasm = load_verifier_time(results_dir / f"{prefix}_wasm_verifier_time.json")
    mean = np.array([native[0], wasm[0]], dtype=float)
    std = np.array([native[1], wasm[1]], dtype=float)
    return mean, std


def load_resources(results_dir: Path, prefix: str) -> ResourceSeries:
    native_data = read_json(results_dir / f"{prefix}_native_resources.json")
    wasm_data = read_json(results_dir / f"{prefix}_wasm_resources.json")

    rss_native = load_mean_std(native_data, "rss_kb")
    rss_wasm = load_mean_std(wasm_data, "rss_kb")
    cpu_native = load_mean_std(native_data, "cpu_pct")
    cpu_wasm = load_mean_std(wasm_data, "cpu_pct")

    return ResourceSeries(
        rss_mean=np.array([rss_native[0], rss_wasm[0]], dtype=float),
        rss_std=np.array([rss_native[1], rss_wasm[1]], dtype=float),
        cpu_mean=np.array([cpu_native[0], cpu_wasm[0]], dtype=float),
        cpu_std=np.array([cpu_native[1], cpu_wasm[1]], dtype=float),
    )


def load_breakdown(results_dir: Path, prefix: str) -> BreakdownSeries:
    native_data = read_json(results_dir / f"{prefix}_native_step_breakdown.json")
    wasm_data = read_json(results_dir / f"{prefix}_wasm_step_breakdown.json")

    keys = ["cert_chain_ms", "signature_ms", "others_ms"]
    labels = ["cert chain\nverification", "signature\nverification", "others"]

    native_means = []
    native_stds = []
    wasm_means = []
    wasm_stds = []
    for key in keys:
        native_mean, native_std = load_mean_std(native_data, key)
        wasm_mean, wasm_std = load_mean_std(wasm_data, key)
        native_means.append(native_mean)
        native_stds.append(native_std)
        wasm_means.append(wasm_mean)
        wasm_stds.append(wasm_std)

    return BreakdownSeries(
        labels=labels,
        native_mean=np.array(native_means, dtype=float),
        native_std=np.array(native_stds, dtype=float),
        wasm_mean=np.array(wasm_means, dtype=float),
        wasm_std=np.array(wasm_stds, dtype=float),
    )


def nice_limit(max_val: float, pad: float = 5.0, step: float = 5.0) -> float:
    limit = max_val + pad
    return max(step * 2, math.ceil(limit / step) * step)


def set_rcparams(base_font: float, title_font: float, fonttype: int) -> None:
    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": base_font,
        "axes.titlesize": title_font,
        "axes.labelsize": base_font,
        "xtick.labelsize": base_font,
        "ytick.labelsize": base_font,
        "axes.linewidth": 1.1,
        "xtick.major.width": 1.1,
        "ytick.major.width": 1.1,
        "xtick.major.size": 3.5,
        "ytick.major.size": 3.5,
        "pdf.fonttype": fonttype,
        "ps.fonttype": fonttype,
    })


def apply_subplot_margins(fig: plt.Figure, default: dict, separate: bool) -> None:
    if separate:
        fig.subplots_adjust(**PAPER_SUBPLOT)
    else:
        fig.subplots_adjust(**default)


def format_value(mean: float, std: float, layout: str = "inline") -> str:
    if layout == "stacked":
        return f"{mean:.2f}\n+/- {std:.2f}"
    if layout == "stacked_std":
        return f"{mean:.2f}\n+/- {std:.2f}"
    return f"{mean:.2f} +/- {std:.2f}"


def bar_compare(
    ax: plt.Axes,
    labels: list[str],
    mean: np.ndarray,
    std: np.ndarray,
    colors: list[str],
    ylabel: str,
    title: str | None,
    show_values: bool,
    axis_max: float | None = None,
    pad_ratio: float = 0.04,
    value_layout: str = "inline",
    headroom_ratio: float | None = None,
    value_fontsize: float | None = None,
    xmargin: float | None = None,
    xspacing: float = 1.0,
) -> None:
    is_stacked = value_layout == "stacked"
    is_multiline = value_layout in {"stacked", "stacked_std"}
    x = np.arange(len(labels)) * xspacing
    raw_max = float(np.max(mean + std))
    ax.bar(
        x,
        mean,
        yerr=std,
        capsize=3.5,
        color=colors,
        edgecolor="none",
        alpha=0.9,
        error_kw={"elinewidth": 1.3, "capthick": 1.3},
    )
    ax.set_xticks(x, labels)
    ax.set_ylabel(ylabel)
    if title:
        ax.set_title(title, pad=6)

    if axis_max is None:
        axis_max = nice_limit(raw_max)
    headroom = 0.0
    if show_values:
        if headroom_ratio is None:
            headroom = max(raw_max * 0.18, axis_max * 0.10, 1.2)
            if is_multiline:
                headroom = max(headroom, raw_max * 0.28, 2.0)
        else:
            headroom = max(raw_max * headroom_ratio, 1.2)
        axis_max = max(axis_max, raw_max + headroom)
    ax.set_ylim(0, axis_max)
    ax.grid(axis="y", linestyle="--", linewidth=1.0, alpha=0.6)
    ax.set_axisbelow(True)
    if show_values:
        # Add a bit of horizontal padding so edge labels don't touch the border.
        ax.margins(x=0.12 if xmargin is None else xmargin)

    if show_values:
        offset = axis_max * pad_ratio * (0.7 if is_multiline else 1.0)
        offset = max(offset, axis_max * 0.01)
        if value_fontsize is None:
            label_fs = max(
                plt.rcParams["font.size"] - (2.2 if is_multiline else 1.5) + NUMERIC_LABEL_DELTA,
                6.5,
            )
        else:
            label_fs = value_fontsize
        for xi, m, s in zip(x, mean, std):
            label = format_value(m, s, layout=value_layout)
            desired_y = m + s + offset
            cap_y = axis_max - max(headroom * 0.35, offset * 0.6)
            if is_stacked:
                top_pad = max(axis_max * 0.08, 1.5)
                cap_y = min(cap_y, axis_max - top_pad)
            if desired_y <= cap_y:
                y = desired_y
                va = "bottom"
            else:
                y = cap_y
                va = "top" if is_stacked else "bottom"
            ax.text(
                xi,
                y,
                label,
                ha="center",
                va=va,
                fontsize=label_fs,
            )


def build_paper_bars(
    labels: list[str],
    mean: np.ndarray,
    std: np.ndarray,
    fig_w: float,
    fig_h: float,
    show_values: bool,
    ylabel: str,
    title: str | None = None,
    axis_max: float | None = None,
    pad_ratio: float = 0.04,
    value_layout: str = "inline",
    separate: bool = False,
    colors: list[str] | None = None,
    tick_labelsize: float | None = None,
    value_fontsize: float | None = None,
    xmargin: float | None = None,
    xspacing: float = 1.0,
    margins: dict | None = None,
) -> plt.Figure:
    if colors is None:
        colors = paper_bar_colors(len(labels) // 2)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=300)
    default_margins = {"left": 0.18, "right": 0.98, "top": 0.94, "bottom": 0.18}
    apply_subplot_margins(fig, margins or default_margins, separate)
    if axis_max is None:
        axis_max = nice_limit(float(np.max(mean + std)), pad=5.0, step=10.0)
    bar_compare(
        ax,
        labels,
        mean,
        std,
        colors,
        ylabel,
        title,
        show_values,
        axis_max=axis_max,
        pad_ratio=pad_ratio,
        value_layout=value_layout,
        headroom_ratio=PAPER_HEADROOM_RATIO if separate else None,
        value_fontsize=value_fontsize,
        xmargin=xmargin,
        xspacing=xspacing,
    )
    if tick_labelsize is not None:
        ax.tick_params(axis="x", labelsize=tick_labelsize, pad=2)
    return fig

def build_latency_pair_twopanel(
    platform_label: str,
    series: LatencySeries,
    fig_w: float,
    fig_h: float,
    show_values: bool,
    shared_axis_max: bool = True,
    show_titles: bool = True,
    separate: bool = False,
) -> plt.Figure:
    labels = ["native\nTrustee AS", "Wasm-based\nAS"]
    colors = ["#81c784", "#63b5f6"]

    axis_max_e2e, axis_max_ver = latency_pair_axis_max(series, shared_axis_max)

    fig, axes = plt.subplots(ncols=2, figsize=(fig_w, fig_h), dpi=300)
    apply_subplot_margins(
        fig,
        {"left": 0.10, "right": 0.98, "top": 0.86, "bottom": 0.22, "wspace": 0.38},
        separate,
    )

    bar_compare(
        axes[0],
        labels,
        series.e2e_mean,
        series.e2e_std,
        colors,
        "Time (ms)",
        f"(a) {platform_label}\nEnd-to-End Attestation Latency (mean +/- std)" if show_titles else None,
        show_values,
        axis_max=axis_max_e2e,
        headroom_ratio=PAPER_HEADROOM_RATIO if separate else None,
    )
    bar_compare(
        axes[1],
        labels,
        series.ver_mean,
        series.ver_std,
        colors,
        "Time (ms)",
        f"(b) {platform_label}\nVerification Time (mean +/- std)" if show_titles else None,
        show_values,
        axis_max=axis_max_ver,
        headroom_ratio=PAPER_HEADROOM_RATIO if separate else None,
    )
    return fig


def build_breakdown_twopanel(
    platform_label: str,
    breakdown: BreakdownSeries,
    fig_w: float,
    fig_h: float,
    show_values: bool,
    show_titles: bool = True,
    separate: bool = False,
) -> plt.Figure:
    colors = ["#81c784", "#63b5f6"]
    axis_max = nice_limit(float(max(
        np.max(breakdown.wasm_mean + breakdown.wasm_std),
        np.max(breakdown.native_mean + breakdown.native_std),
    )), pad=2.0, step=2.0)

    fig, axes = plt.subplots(ncols=2, figsize=(fig_w, fig_h), dpi=300)
    apply_subplot_margins(
        fig,
        {"left": 0.10, "right": 0.98, "top": 0.86, "bottom": 0.22, "wspace": 0.38},
        separate,
    )

    bar_compare(
        axes[0],
        breakdown.labels,
        breakdown.native_mean,
        breakdown.native_std,
        [colors[0]] * len(breakdown.labels),
        "Time (ms)",
        "(a) Native Verification Time" if show_titles else None,
        show_values,
        axis_max=axis_max,
        pad_ratio=0.03,
        value_layout="stacked",
        headroom_ratio=PAPER_HEADROOM_RATIO if separate else None,
    )
    axes[0].tick_params(axis="x", labelsize=max(plt.rcParams["font.size"] - 2.2, 6.2), pad=2)
    bar_compare(
        axes[1],
        breakdown.labels,
        breakdown.wasm_mean,
        breakdown.wasm_std,
        [colors[1]] * len(breakdown.labels),
        "Time (ms)",
        "(b) Wasm Verification Time" if show_titles else None,
        show_values,
        axis_max=axis_max,
        pad_ratio=0.03,
        value_layout="stacked",
        headroom_ratio=PAPER_HEADROOM_RATIO if separate else None,
    )
    axes[1].tick_params(axis="x", labelsize=max(plt.rcParams["font.size"] - 2.2, 6.2), pad=2)
    return fig


def build_single_latency(
    title: str,
    mean: np.ndarray,
    std: np.ndarray,
    fig_w: float,
    fig_h: float,
    show_values: bool,
    show_title: bool = True,
    value_layout: str = "inline",
    axis_max: float | None = None,
    separate: bool = False,
) -> plt.Figure:
    labels = ["native\nTrustee AS", "Wasm-based\nAS"]
    colors = ["#81c784", "#63b5f6"]

    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=300)
    apply_subplot_margins(fig, {"left": 0.18, "right": 0.98, "top": 0.94, "bottom": 0.18}, separate)
    if axis_max is None:
        axis_max = nice_limit(float(np.max(mean + std)), pad=5.0, step=10.0)
    bar_compare(
        ax,
        labels,
        mean,
        std,
        colors,
        "Time (ms)",
        title if show_title else None,
        show_values,
        axis_max=axis_max,
        value_layout=value_layout,
        headroom_ratio=PAPER_HEADROOM_RATIO if separate else None,
    )
    return fig


def build_resources_twopanel(
    platform_label: str,
    resources: ResourceSeries,
    fig_w: float,
    fig_h: float,
    show_values: bool,
    show_titles: bool = True,
    separate: bool = False,
) -> plt.Figure:
    labels = ["native\nTrustee AS", "Wasm-based\nAS"]
    colors = ["#81c784", "#63b5f6"]

    fig, axes = plt.subplots(ncols=2, figsize=(fig_w, fig_h), dpi=300)
    apply_subplot_margins(
        fig,
        {"left": 0.10, "right": 0.98, "top": 0.86, "bottom": 0.22, "wspace": 0.38},
        separate,
    )

    rss_mean_mb = resources.rss_mean / 1024.0
    rss_std_mb = resources.rss_std / 1024.0
    bar_compare(
        axes[0],
        labels,
        rss_mean_mb,
        rss_std_mb,
        colors,
        "RSS (MB)",
        f"(a) {platform_label}\nRSS usage during attestation" if show_titles else None,
        show_values,
        axis_max=nice_limit(float(np.max(rss_mean_mb + rss_std_mb)), pad=2.0, step=10.0),
        pad_ratio=0.02,
        headroom_ratio=PAPER_HEADROOM_RATIO if separate else None,
    )
    bar_compare(
        axes[1],
        labels,
        resources.cpu_mean,
        resources.cpu_std,
        colors,
        "CPU (%)",
        f"(b) {platform_label}\nCPU usage during attestation" if show_titles else None,
        show_values,
        axis_max=nice_limit(float(np.max(resources.cpu_mean + resources.cpu_std)), pad=0.4, step=1.0),
        pad_ratio=0.08,
        headroom_ratio=PAPER_HEADROOM_RATIO if separate else None,
    )
    return fig


def build_breakdown_panel(
    breakdown: BreakdownSeries,
    fig_w: float,
    fig_h: float,
    show_values: bool,
    panel: str,
    show_title: bool = True,
    separate: bool = False,
) -> plt.Figure:
    colors = ["#81c784", "#63b5f6"]
    axis_max = nice_limit(float(max(
        np.max(breakdown.wasm_mean + breakdown.wasm_std),
        np.max(breakdown.native_mean + breakdown.native_std),
    )), pad=2.0, step=2.0)

    if panel == "native":
        mean = breakdown.native_mean
        std = breakdown.native_std
        title = "(a) Native Verification Time"
        bar_colors = [colors[0]] * len(breakdown.labels)
    elif panel == "wasm":
        mean = breakdown.wasm_mean
        std = breakdown.wasm_std
        title = "(b) Wasm Verification Time"
        bar_colors = [colors[1]] * len(breakdown.labels)
    else:
        raise ValueError(f"unknown breakdown panel: {panel}")

    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=300)
    apply_subplot_margins(fig, {"left": 0.18, "right": 0.98, "top": 0.88, "bottom": 0.24}, separate)
    bar_compare(
        ax,
        breakdown.labels,
        mean,
        std,
        bar_colors,
        "Time (ms)",
        title if show_title else None,
        show_values,
        axis_max=axis_max,
        pad_ratio=0.03,
        value_layout="stacked",
        headroom_ratio=PAPER_HEADROOM_RATIO if separate else None,
    )
    ax.tick_params(axis="x", labelsize=max(plt.rcParams["font.size"] - 2.2, 6.2), pad=2)
    return fig


def build_resources_panel(
    platform_label: str,
    resources: ResourceSeries,
    fig_w: float,
    fig_h: float,
    show_values: bool,
    panel: str,
    show_title: bool = True,
    separate: bool = False,
) -> plt.Figure:
    labels = ["native\nTrustee AS", "Wasm-based\nAS"]
    colors = ["#81c784", "#63b5f6"]

    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=300)
    apply_subplot_margins(fig, {"left": 0.18, "right": 0.98, "top": 0.88, "bottom": 0.22}, separate)

    if panel == "rss":
        rss_mean_mb = resources.rss_mean / 1024.0
        rss_std_mb = resources.rss_std / 1024.0
        title = f"(a) {platform_label}\nRSS usage during attestation"
        axis_max = nice_limit(float(np.max(rss_mean_mb + rss_std_mb)), pad=2.0, step=10.0)
        bar_compare(
            ax,
            labels,
            rss_mean_mb,
            rss_std_mb,
            colors,
            "RSS (MB)",
            title if show_title else None,
            show_values,
            axis_max=axis_max,
            pad_ratio=0.02,
            headroom_ratio=PAPER_HEADROOM_RATIO if separate else None,
        )
    elif panel == "cpu":
        title = f"(b) {platform_label}\nCPU usage during attestation"
        axis_max = nice_limit(float(np.max(resources.cpu_mean + resources.cpu_std)), pad=0.4, step=1.0)
        bar_compare(
            ax,
            labels,
            resources.cpu_mean,
            resources.cpu_std,
            colors,
            "CPU (%)",
            title if show_title else None,
            show_values,
            axis_max=axis_max,
            pad_ratio=0.08,
            headroom_ratio=PAPER_HEADROOM_RATIO if separate else None,
        )
    else:
        raise ValueError(f"unknown resources panel: {panel}")

    return fig


def latency_pair_axis_max(series: LatencySeries, shared_axis_max: bool) -> tuple[float, float]:
    if shared_axis_max:
        axis_max = nice_limit(float(max(
            np.max(series.e2e_mean + series.e2e_std),
            np.max(series.ver_mean + series.ver_std),
        )))
        return axis_max, axis_max
    axis_max_e2e = nice_limit(float(np.max(series.e2e_mean + series.e2e_std)))
    axis_max_ver = nice_limit(float(np.max(series.ver_mean + series.ver_std)))
    return axis_max_e2e, axis_max_ver


def build_dumbbell_onecol(
    platform: str,
    series: LatencySeries,
    fig_w: float,
    fig_h: float,
    show_values: bool,
    show_title: bool = True,
    separate: bool = False,
) -> plt.Figure:
    green = "#81c784"
    blue = "#63b5f6"

    metrics = ["E2E latency", "Verify time"]
    native_mean = np.array([series.e2e_mean[0], series.ver_mean[0]], dtype=float)
    native_std = np.array([series.e2e_std[0], series.ver_std[0]], dtype=float)
    wasm_mean = np.array([series.e2e_mean[1], series.ver_mean[1]], dtype=float)
    wasm_std = np.array([series.e2e_std[1], series.ver_std[1]], dtype=float)

    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=300)
    apply_subplot_margins(fig, {"left": 0.33, "right": 0.98, "top": 0.82, "bottom": 0.34}, separate)

    y = np.arange(len(metrics))[::-1]
    ax.set_yticks(y, metrics)
    ax.set_ylim(-0.45, 1.45)

    for yi, a, b in zip(y, native_mean, wasm_mean):
        ax.plot([a, b], [yi, yi], linewidth=2.0, alpha=0.55)

    ax.errorbar(native_mean, y, xerr=native_std, fmt="o", capsize=3.5,
                elinewidth=1.6, capthick=1.6, label="Native", color=green)
    ax.errorbar(wasm_mean, y, xerr=wasm_std, fmt="o", capsize=3.5,
                elinewidth=1.6, capthick=1.6, label="Wasm", color=blue)

    max_val = float(max(
        np.max(native_mean + native_std),
        np.max(wasm_mean + wasm_std),
    ))
    axis_max = nice_limit(max_val)
    ax.set_xlim(0, axis_max)
    ax.set_xlabel("Time (ms)")
    ax.grid(axis="x", linestyle="--", linewidth=1.0, alpha=0.6)
    if show_title:
        ax.set_title(f"{platform} latency (mean +/- std)", pad=10)

    if show_values:
        value_fs = max(plt.rcParams["font.size"] - 1.0 + NUMERIC_LABEL_DELTA, 9.2)
        for i in range(len(metrics)):
            yi = y[i]
            if yi == y.max():
                ax.annotate(
                    format_value(native_mean[i], native_std[i]),
                    (native_mean[i], yi),
                    xytext=(6, -10), textcoords="offset points",
                    ha="left", va="top", fontsize=value_fs,
                )
                ax.annotate(
                    format_value(wasm_mean[i], wasm_std[i]),
                    (wasm_mean[i], yi),
                    xytext=(-6, 8), textcoords="offset points",
                    ha="right", va="bottom", fontsize=value_fs,
                )
            else:
                ax.annotate(
                    format_value(native_mean[i], native_std[i]),
                    (native_mean[i], yi),
                    xytext=(6, 8), textcoords="offset points",
                    ha="left", va="bottom", fontsize=value_fs,
                )
                ax.annotate(
                    format_value(wasm_mean[i], wasm_std[i]),
                    (wasm_mean[i], yi),
                    xytext=(-6, -10), textcoords="offset points",
                    ha="right", va="top", fontsize=value_fs,
                )

    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.42),
              ncol=2, columnspacing=1.2, handletextpad=0.6)
    return fig


def build_bars_breakdown_onecol(
    platform: str,
    series: LatencySeries,
    fig_w: float,
    fig_h: float,
    show_values: bool,
    show_title: bool = True,
    separate: bool = False,
) -> plt.Figure:
    from matplotlib.lines import Line2D

    verify_fill = "#63b5f6"
    other_fill = "#d9d9d9"

    verify_marker_color = "#1f77b4"
    e2e_marker_color = "#6e6e6e"

    # Ensure stacked bars never go negative if verification exceeds end-to-end.
    raw_e2e = np.maximum(series.e2e_mean, series.ver_mean)
    raw_ver = series.ver_mean
    scale = 0.001 if float(np.max(raw_e2e)) >= 1000.0 else 1.0
    unit = "s" if scale < 1.0 else "ms"

    e2e_mean = raw_e2e * scale
    e2e_std = series.e2e_std * scale
    ver_mean = raw_ver * scale
    ver_std = series.ver_std * scale
    other_mean = np.maximum(e2e_mean - ver_mean, 0.0)

    labels = ["Native\nTrustee AS", "Wasm-based\nAS"]
    x = np.arange(len(labels))

    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=300)
    apply_subplot_margins(fig, {"left": 0.20, "right": 0.98, "top": 0.88, "bottom": 0.30}, separate)

    width = 0.62

    ax.bar(x, ver_mean, width=width, color=verify_fill, edgecolor="none", alpha=0.65)
    ax.bar(x, other_mean, width=width, bottom=ver_mean, color=other_fill,
           edgecolor="none", alpha=0.95)

    for i, xi in enumerate(x):
        ax.plot(
            xi, ver_mean[i],
            marker="o", markersize=6.2,
            markerfacecolor=verify_marker_color,
            markeredgecolor="black", markeredgewidth=0.6,
            linestyle="none", zorder=7,
        )
        ax.plot(
            xi, e2e_mean[i],
            marker="^", markersize=6.8,
            markerfacecolor=e2e_marker_color,
            markeredgecolor="black", markeredgewidth=0.6,
            linestyle="none", zorder=7,
        )

    max_val = float(np.max(e2e_mean + e2e_std))
    axis_max = nice_limit(max_val)
    if show_values:
        min_pad = 0.2 if unit == "s" else 4.0
        axis_max = max(axis_max, max_val + max(max_val * 0.22, min_pad))
    ax.set_ylabel(f"Time ({unit})")
    ax.set_ylim(0, axis_max)
    if unit == "s":
        step = 0.5 if axis_max <= 5 else 1.0
        ax.set_yticks(np.arange(0, axis_max + step * 0.5, step))
    else:
        ax.set_yticks(np.arange(0, axis_max + 0.1, 10))
    ax.set_xticks(x, labels)
    ax.grid(axis="y", linestyle="--", linewidth=1.0, alpha=0.6)
    ax.set_axisbelow(True)
    if show_title:
        ax.set_title(f"{platform} latency breakdown (mean +/- std)")

    if show_values:
        base = plt.rcParams["font.size"]
        fs_total = max(base - 1.8 + NUMERIC_LABEL_DELTA, 7.0)
        fs_ver = max(base - 2.8 + NUMERIC_LABEL_DELTA, 6.4)

        for i, xi in enumerate(x):
            total_label_y = e2e_mean[i]
            ax.annotate(
                format_value(e2e_mean[i], e2e_std[i]),
                (xi, total_label_y),
                xytext=(0, 5), textcoords="offset points",
                ha="center", va="bottom", fontsize=fs_total,
            )

            gap = max(total_label_y - ver_mean[i], 0.0)
            threshold = max(axis_max * 0.06, 6.0)
            if gap < threshold:
                # When the top segment is tiny, keep the label inside the lower bar.
                ver_y = max(ver_mean[i] * 0.5, axis_max * 0.03)
                ax.text(
                    xi, ver_y,
                    format_value(ver_mean[i], ver_std[i]),
                    ha="center", va="center", fontsize=fs_ver,
                    clip_on=False,
                )
            else:
                # Place above the lower segment for clearer separation.
                ax.annotate(
                    format_value(ver_mean[i], ver_std[i]),
                    (xi, ver_mean[i]),
                    xytext=(0, 4), textcoords="offset points",
                    ha="center", va="bottom", fontsize=fs_ver,
                )

    handles = [
        Line2D([0], [0], marker="o", linestyle="none",
               markerfacecolor=verify_marker_color, markeredgecolor="black",
               markeredgewidth=0.6, markersize=6.2, label="Verification time"),
        Line2D([0], [0], marker="^", linestyle="none",
               markerfacecolor=e2e_marker_color, markeredgecolor="black",
               markeredgewidth=0.6, markersize=6.8, label="E2E Attestation"),
    ]
    ax.legend(
        handles=handles, frameon=False,
        loc="upper center", bbox_to_anchor=(0.5, -0.23),
        ncol=2, columnspacing=1.2, handletextpad=0.6,
    )
    return fig


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Generate evaluation figures from JSON.")
    ap.add_argument("--results-dir", default=".", help="Directory with JSON results.")
    ap.add_argument("--output-dir", default=None, help="Directory to place figures.")
    ap.add_argument("--preset", choices=["onecol", "evaluation", "evaluation-all"], default="onecol")
    ap.add_argument("--figures", nargs="*", type=int, help="Figure numbers for evaluation preset.")
    ap.add_argument("--strict", action="store_true", help="Fail if inputs are missing.")
    ap.add_argument("--platform", choices=["snp", "tdx", "all"], default="all")
    ap.add_argument("--style", choices=["dumbbell", "bars", "all"], default="all")
    ap.add_argument("--output", default=None, help="Output file (single platform/style).")
    ap.add_argument("--format", choices=["pdf", "png"], default="pdf")
    ap.add_argument("--figwidth", type=float, default=3.35)
    ap.add_argument("--figheight", type=float, default=None)
    ap.add_argument("--font", type=float, default=10.5)
    ap.add_argument("--titlefont", type=float, default=11.5)
    ap.add_argument("--pdf-fonttype", type=int, choices=[3, 42], default=3)
    ap.add_argument("--no-values", action="store_true", help="Hide numeric labels.")
    ap.add_argument(
        "--separate",
        action="store_true",
        help="Hide titles/captions and split two-panel evaluation figures.",
    )
    ap.add_argument(
        "--paper",
        action="store_true",
        help="Paper mode: like --separate but with merged evaluation figures and paper labels.",
    )
    args = ap.parse_args()
    if args.paper and args.separate:
        ap.error("--paper and --separate cannot be used together.")
    return args


def default_figheight(style: str) -> float:
    return 2.85 if style == "dumbbell" else 3.15


def evaluation_figheight(fig_number: int, fallback: float | None) -> float:
    if fallback is not None:
        return fallback
    if fig_number in {21, 22, 24, 25, 27}:
        return 2.6
    return 2.2


def ensure_files(paths: list[Path], strict: bool, fig_number: int) -> bool:
    missing = [path for path in paths if not path.is_file()]
    if not missing:
        return True
    msg = f"[warn] figure {fig_number} skipped (missing: " + ", ".join(str(p) for p in missing) + ")"
    if strict:
        raise FileNotFoundError(msg)
    print(msg)
    return False


def generate_evaluation_figures_paper(args: argparse.Namespace) -> int:
    results_dir = Path(args.results_dir)
    output_dir = Path(args.output_dir) if args.output_dir else results_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.output:
        raise SystemExit("--output is only valid for --preset onecol.")

    if matplotlib.__version__ != "3.10.3":
        print(f"[warn] matplotlib=={matplotlib.__version__} (original metadata was v3.10.3)")

    set_rcparams(args.font, args.titlefont, args.pdf_fonttype)
    show_values = not args.no_values
    savefig_kwargs: dict = {}

    default_figs = list(range(21, 31))
    fig_numbers = args.figures if args.figures else default_figs
    for fig_number in fig_numbers:
        if fig_number < 21 or fig_number > 30:
            raise SystemExit("Evaluation preset supports figure numbers 21-30.")

    use_default_width = abs(args.figwidth - DEFAULT_FIGWIDTH) < 1e-6
    fig_w = PAPER_FIGWIDTH if use_default_width else args.figwidth
    fig_h = PAPER_FIGHEIGHT if args.figheight is None else args.figheight
    dense_tick = paper_dense_tick_labelsize(multiline=True)
    dense_value = paper_dense_value_fontsize()
    dense_xmargin = 0.06
    dense_spacing = 1.22
    breakdown_spacing = 1.6

    snp_label = paper_tee_label("snp")
    tdx_label = paper_tee_label("tdx")
    snp_labels = paper_bar_labels([snp_label])
    tdx_labels = paper_bar_labels([tdx_label])
    snp_tdx_labels = paper_bar_labels([snp_label, tdx_label])

    snp_platform_files = [
        results_dir / "snp_native_latency.json",
        results_dir / "snp_wasm_latency.json",
        results_dir / "snp_native_verifier_time.json",
        results_dir / "snp_wasm_verifier_time.json",
    ]
    tdx_platform_files = [
        results_dir / "tdx_native_latency.json",
        results_dir / "tdx_wasm_latency.json",
        results_dir / "tdx_native_verifier_time.json",
        results_dir / "tdx_wasm_verifier_time.json",
    ]
    snp_resources_files = [
        results_dir / "snp_native_resources.json",
        results_dir / "snp_wasm_resources.json",
    ]
    tdx_resources_files = [
        results_dir / "tdx_native_resources.json",
        results_dir / "tdx_wasm_resources.json",
    ]
    snp_breakdown_files = [
        results_dir / "snp_native_step_breakdown.json",
        results_dir / "snp_wasm_step_breakdown.json",
    ]

    requested = set(fig_numbers)
    to_generate = {
        "21a": 21 in requested,
        "21b": 21 in requested,
        "22a": 22 in requested,
        "22b": 22 in requested,
        "23": 23 in requested,
        "24a": 24 in requested,
        "24b": 24 in requested,
        "25a": 25 in requested,
        "25b": 25 in requested,
        "26": 26 in requested,
        "27a": 27 in requested,
        "27b": 27 in requested,
        "28": 28 in requested,
        "29": 29 in requested,
        "30": 30 in requested,
    }
    suppress_standalone_21a = True
    suppress_standalone_22 = True
    suppress_standalone_30 = True
    suppress_paper_resources = True
    if suppress_paper_resources:
        to_generate["24a"] = False
        to_generate["24b"] = False
        to_generate["27a"] = False
        to_generate["27b"] = False

    eval_index = 0
    generated = 0

    def save_figure(fig: plt.Figure, desc: str) -> None:
        nonlocal eval_index, generated
        eval_index += 1
        out_path = output_dir / f"eval{eval_index}_{desc}.{args.format}"
        fig.savefig(out_path, **savefig_kwargs)
        plt.close(fig)
        print(f"Wrote: {out_path}")
        generated += 1

    def time_axis_max(mean: np.ndarray, std: np.ndarray, step: float = 10.0) -> float:
        return nice_limit(float(np.max(mean + std)), pad=5.0, step=step)

    def files_exist(paths: list[Path]) -> bool:
        return all(path.is_file() for path in paths)

    # Merge fig23 + fig25a (latency no cache).
    if to_generate["23"] and to_generate["25a"]:
        needed = [
            results_dir / "snp_native_latency_no_cert.json",
            results_dir / "snp_wasm_latency_no_cert.json",
            *tdx_platform_files,
        ]
        if files_exist(needed):
            snp_mean, snp_std = load_latency_pair(results_dir, "snp", "latency_no_cert")
            tdx_series = load_platform(results_dir, "tdx")
            mean = np.concatenate([snp_mean, tdx_series.e2e_mean])
            std = np.concatenate([snp_std, tdx_series.e2e_std])
            axis_max = time_axis_max(mean, std, step=10.0)
            fig = build_paper_bars(
                snp_tdx_labels,
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                "Time (ms)",
                axis_max=axis_max,
                separate=True,
                tick_labelsize=dense_tick,
                value_fontsize=dense_value,
                xmargin=dense_xmargin,
                value_layout="stacked_std",
                xspacing=dense_spacing,
            )
            save_figure(fig, "snp_tdx_with_collateral_latency")
            to_generate["23"] = False
            to_generate["25a"] = False
        elif args.strict:
            ensure_files(needed, args.strict, 23)

    # Merge fig21a + fig30 (SNP latency + TDX latency without collateral).
    if to_generate["21a"] and to_generate["30"]:
        needed = [
            results_dir / "snp_native_latency.json",
            results_dir / "snp_wasm_latency.json",
            results_dir / "tdx_native_latency_no_collateral.json",
            results_dir / "tdx_wasm_latency_no_collateral.json",
        ]
        if files_exist(needed):
            snp_series = load_platform(results_dir, "snp")
            tdx_mean, tdx_std = load_latency_pair(results_dir, "tdx", "latency_no_collateral")
            mean = np.concatenate([snp_series.e2e_mean, tdx_mean])
            std = np.concatenate([snp_series.e2e_std, tdx_std])
            axis_max = time_axis_max(mean, std, step=10.0)
            fig = build_paper_bars(
                snp_tdx_labels,
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                "Time (ms)",
                axis_max=axis_max,
                separate=True,
                tick_labelsize=dense_tick,
                value_fontsize=dense_value,
                xmargin=dense_xmargin,
                value_layout="stacked_std",
                xspacing=dense_spacing,
            )
            save_figure(fig, "snp_tdx_latency_no_collateral")
            to_generate["21a"] = False
            to_generate["30"] = False
        elif args.strict:
            ensure_files(needed, args.strict, 21)

    # Merge fig21b + fig25b (verification cache).
    if to_generate["21b"] and to_generate["25b"]:
        needed = [*snp_platform_files, *tdx_platform_files]
        if files_exist(needed):
            snp_series = load_platform(results_dir, "snp")
            tdx_series = load_platform(results_dir, "tdx")
            mean = np.concatenate([snp_series.ver_mean, tdx_series.ver_mean])
            std = np.concatenate([snp_series.ver_std, tdx_series.ver_std])
            axis_max = time_axis_max(mean, std, step=5.0)
            fig = build_paper_bars(
                snp_tdx_labels,
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                "Time (ms)",
                axis_max=axis_max,
                separate=True,
                tick_labelsize=dense_tick,
                value_fontsize=dense_value,
                xmargin=dense_xmargin,
                value_layout="stacked_std",
                xspacing=dense_spacing,
            )
            save_figure(fig, "snp_tdx_verification_time")
            to_generate["21b"] = False
            to_generate["25b"] = False
        elif args.strict:
            ensure_files(needed, args.strict, 21)

    # Merge fig22a + fig22b (snp breakdown).
    if to_generate["22a"] and to_generate["22b"]:
        if files_exist(snp_breakdown_files):
            breakdown = load_breakdown(results_dir, "snp")
            primary = breakdown.labels
            labels = [value for label in primary for value in (label, "")]
            mean = np.column_stack([breakdown.native_mean, breakdown.wasm_mean]).reshape(-1)
            std = np.column_stack([breakdown.native_std, breakdown.wasm_std]).reshape(-1)
            axis_max = nice_limit(float(max(
                np.max(breakdown.wasm_mean + breakdown.wasm_std),
                np.max(breakdown.native_mean + breakdown.native_std),
            )), pad=2.0, step=2.0)
            tick_fs = paper_dense_tick_labelsize(multiline=True)
            dense_stacked = paper_dense_value_fontsize(stacked=True)
            fig = build_paper_bars(
                labels,
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                "Time (ms)",
                axis_max=axis_max,
                pad_ratio=0.03,
                value_layout="stacked",
                separate=True,
                colors=paper_bar_colors(len(primary)),
                tick_labelsize=tick_fs,
                value_fontsize=dense_stacked,
                xmargin=0.05,
                xspacing=breakdown_spacing,
                margins={"left": 0.18, "right": 0.98, "top": 0.90, "bottom": 0.26},
            )
            from matplotlib.patches import Patch
            ax = fig.axes[0]
            legend_handles = [
                Patch(facecolor=PAPER_NATIVE_COLOR, edgecolor="none", label=PAPER_NATIVE_LABEL),
                Patch(facecolor=PAPER_WASM_COLOR, edgecolor="none", label=PAPER_WASM_LABEL),
            ]
            ax.legend(
                handles=legend_handles,
                frameon=False,
                loc="upper left",
                bbox_to_anchor=(0.0, 0.98),
                borderaxespad=0.2,
                fontsize=max(plt.rcParams["font.size"] - 2.2, 6.5),
            )
            # Center the step labels between each native/Wasm pair.
            pair_positions = (np.arange(len(primary)) * 2) * breakdown_spacing + breakdown_spacing / 2
            ax.set_xticks(pair_positions, primary)
            save_figure(fig, "snp_verification_breakdown_native_wasm")
        elif args.strict:
            ensure_files(snp_breakdown_files, args.strict, 22)

    # Merge fig24a + fig27a (rss).
    if to_generate["24a"] and to_generate["27a"]:
        needed = [*snp_resources_files, *tdx_resources_files]
        if files_exist(needed):
            snp_resources = load_resources(results_dir, "snp")
            tdx_resources = load_resources(results_dir, "tdx")
            mean = np.concatenate([snp_resources.rss_mean, tdx_resources.rss_mean]) / 1024.0
            std = np.concatenate([snp_resources.rss_std, tdx_resources.rss_std]) / 1024.0
            axis_max = nice_limit(float(np.max(mean + std)), pad=2.0, step=10.0)
            fig = build_paper_bars(
                snp_tdx_labels,
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                "RSS (MB)",
                axis_max=axis_max,
                pad_ratio=0.02,
                separate=True,
                tick_labelsize=dense_tick,
                value_fontsize=dense_value,
                xmargin=dense_xmargin,
                value_layout="stacked_std",
                xspacing=dense_spacing,
            )
            save_figure(fig, "snp_tdx_resources_rss")
            to_generate["24a"] = False
            to_generate["27a"] = False
        elif args.strict:
            ensure_files(needed, args.strict, 24)

    # Merge fig24b + fig27b (cpu).
    if to_generate["24b"] and to_generate["27b"]:
        needed = [*snp_resources_files, *tdx_resources_files]
        if files_exist(needed):
            snp_resources = load_resources(results_dir, "snp")
            tdx_resources = load_resources(results_dir, "tdx")
            mean = np.concatenate([snp_resources.cpu_mean, tdx_resources.cpu_mean])
            std = np.concatenate([snp_resources.cpu_std, tdx_resources.cpu_std])
            axis_max = nice_limit(float(np.max(mean + std)), pad=0.4, step=1.0)
            fig = build_paper_bars(
                snp_tdx_labels,
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                "CPU (%)",
                axis_max=axis_max,
                pad_ratio=0.08,
                separate=True,
                tick_labelsize=dense_tick,
                value_fontsize=dense_value,
                xmargin=dense_xmargin,
                value_layout="stacked_std",
                xspacing=dense_spacing,
            )
            save_figure(fig, "snp_tdx_resources_cpu")
            to_generate["24b"] = False
            to_generate["27b"] = False
        elif args.strict:
            ensure_files(needed, args.strict, 24)

    # fig21 (latency cached tdx) - a panel
    if to_generate["21a"] or to_generate["21b"]:
        if ensure_files(snp_platform_files, args.strict, 21):
            series = load_platform(results_dir, "snp")
            axis_max_e2e, axis_max_ver = latency_pair_axis_max(series, shared_axis_max=True)
            if to_generate["21a"] and not suppress_standalone_21a:
                fig = build_paper_bars(
                    snp_labels,
                    series.e2e_mean,
                    series.e2e_std,
                    fig_w,
                    fig_h,
                    show_values,
                    "Time (ms)",
                    axis_max=axis_max_e2e,
                    separate=True,
                )
                save_figure(fig, "snp_latency_native_wasm")
            if to_generate["21b"]:
                fig = build_paper_bars(
                    snp_labels,
                    series.ver_mean,
                    series.ver_std,
                    fig_w,
                    fig_h,
                    show_values,
                    "Time (ms)",
                    axis_max=axis_max_ver,
                    separate=True,
                )
                save_figure(fig, "snp_verification_time_native_wasm")

    # fig22 separate panels
    if (to_generate["22a"] or to_generate["22b"]) and not suppress_standalone_22:
        if ensure_files(snp_breakdown_files, args.strict, 22):
            breakdown = load_breakdown(results_dir, "snp")
            primary = breakdown.labels
            axis_max = nice_limit(float(max(
                np.max(breakdown.wasm_mean + breakdown.wasm_std),
                np.max(breakdown.native_mean + breakdown.native_std),
            )), pad=2.0, step=2.0)
            tick_fs = max(plt.rcParams["font.size"] - 2.2, 6.2)
            if to_generate["22a"]:
                labels = primary
                fig = build_paper_bars(
                    labels,
                    breakdown.native_mean,
                    breakdown.native_std,
                    fig_w,
                    fig_h,
                    show_values,
                    "Time (ms)",
                    axis_max=axis_max,
                    pad_ratio=0.03,
                    value_layout="stacked",
                    separate=True,
                    colors=[PAPER_NATIVE_COLOR] * len(labels),
                    tick_labelsize=tick_fs,
                )
                save_figure(fig, "snp_verification_breakdown_native")
            if to_generate["22b"]:
                labels = primary
                fig = build_paper_bars(
                    labels,
                    breakdown.wasm_mean,
                    breakdown.wasm_std,
                    fig_w,
                    fig_h,
                    show_values,
                    "Time (ms)",
                    axis_max=axis_max,
                    pad_ratio=0.03,
                    value_layout="stacked",
                    separate=True,
                    colors=[PAPER_WASM_COLOR] * len(labels),
                    tick_labelsize=tick_fs,
                )
                save_figure(fig, "snp_verification_breakdown_wasm")

    # fig23 (latency no cache)
    if to_generate["23"]:
        needed = [
            results_dir / "snp_native_latency_no_cert.json",
            results_dir / "snp_wasm_latency_no_cert.json",
        ]
        if ensure_files(needed, args.strict, 23):
            mean, std = load_latency_pair(results_dir, "snp", "latency_no_cert")
            axis_max = time_axis_max(mean, std, step=10.0)
            fig = build_paper_bars(
                snp_labels,
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                "Time (ms)",
                axis_max=axis_max,
                separate=True,
            )
            save_figure(fig, "snp_no_cert_latency")

    # fig24 (rss/cpu)
    if to_generate["24a"] or to_generate["24b"]:
        if ensure_files(snp_resources_files, args.strict, 24):
            resources = load_resources(results_dir, "snp")
            if to_generate["24a"]:
                rss_mean_mb = resources.rss_mean / 1024.0
                rss_std_mb = resources.rss_std / 1024.0
                axis_max = nice_limit(float(np.max(rss_mean_mb + rss_std_mb)), pad=2.0, step=10.0)
                fig = build_paper_bars(
                    snp_labels,
                    rss_mean_mb,
                    rss_std_mb,
                    fig_w,
                    fig_h,
                    show_values,
                    "RSS (MB)",
                    axis_max=axis_max,
                    pad_ratio=0.02,
                    separate=True,
                )
                save_figure(fig, "snp_resources_rss")
            if to_generate["24b"]:
                axis_max = nice_limit(float(np.max(resources.cpu_mean + resources.cpu_std)), pad=0.4, step=1.0)
                fig = build_paper_bars(
                    snp_labels,
                    resources.cpu_mean,
                    resources.cpu_std,
                    fig_w,
                    fig_h,
                    show_values,
                    "CPU (%)",
                    axis_max=axis_max,
                    pad_ratio=0.08,
                    separate=True,
                )
                save_figure(fig, "snp_resources_cpu")

    # fig25 (tdx latency/verification)
    if to_generate["25a"] or to_generate["25b"]:
        if ensure_files(tdx_platform_files, args.strict, 25):
            series = load_platform(results_dir, "tdx")
            axis_max_e2e, axis_max_ver = latency_pair_axis_max(series, shared_axis_max=False)
            if to_generate["25a"]:
                fig = build_paper_bars(
                    tdx_labels,
                    series.e2e_mean,
                    series.e2e_std,
                    fig_w,
                    fig_h,
                    show_values,
                    "Time (ms)",
                    axis_max=axis_max_e2e,
                    separate=True,
                )
                save_figure(fig, "tdx_latency_native_wasm")
            if to_generate["25b"]:
                fig = build_paper_bars(
                    tdx_labels,
                    series.ver_mean,
                    series.ver_std,
                    fig_w,
                    fig_h,
                    show_values,
                    "Time (ms)",
                    axis_max=axis_max_ver,
                    separate=True,
                )
                save_figure(fig, "tdx_verification_time_native_wasm")

    # fig26 (verification modified tdx)
    if to_generate["26"]:
        native_path = results_dir / "tdx_native_verifier_time_dcap_qvl.json"
        if not native_path.is_file():
            native_path = results_dir / "tdx_native_verifier_time.json"
        needed = [
            native_path,
            results_dir / "tdx_wasm_verifier_time.json",
        ]
        if ensure_files(needed, args.strict, 26):
            native = load_verifier_time(native_path)
            wasm = load_verifier_time(results_dir / "tdx_wasm_verifier_time.json")
            mean = np.array([native[0], wasm[0]], dtype=float)
            std = np.array([native[1], wasm[1]], dtype=float)
            axis_max = time_axis_max(mean, std, step=10.0)
            fig = build_paper_bars(
                tdx_labels,
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                "Time (ms)",
                axis_max=axis_max,
                separate=True,
            )
            save_figure(fig, "tdx_modified_dcap_verification_time")

    # fig27 (tdx rss/cpu)
    if to_generate["27a"] or to_generate["27b"]:
        if ensure_files(tdx_resources_files, args.strict, 27):
            resources = load_resources(results_dir, "tdx")
            if to_generate["27a"]:
                rss_mean_mb = resources.rss_mean / 1024.0
                rss_std_mb = resources.rss_std / 1024.0
                axis_max = nice_limit(float(np.max(rss_mean_mb + rss_std_mb)), pad=2.0, step=10.0)
                fig = build_paper_bars(
                    tdx_labels,
                    rss_mean_mb,
                    rss_std_mb,
                    fig_w,
                    fig_h,
                    show_values,
                    "RSS (MB)",
                    axis_max=axis_max,
                    pad_ratio=0.02,
                    separate=True,
                )
                save_figure(fig, "tdx_resources_rss")
            if to_generate["27b"]:
                axis_max = nice_limit(float(np.max(resources.cpu_mean + resources.cpu_std)), pad=0.4, step=1.0)
                fig = build_paper_bars(
                    tdx_labels,
                    resources.cpu_mean,
                    resources.cpu_std,
                    fig_w,
                    fig_h,
                    show_values,
                    "CPU (%)",
                    axis_max=axis_max,
                    pad_ratio=0.08,
                    separate=True,
                )
                save_figure(fig, "tdx_resources_cpu")

    # fig28 (latency modified tdx, cold)
    if to_generate["28"]:
        needed = [
            results_dir / "tdx_native_latency_dcap_qvl_cold.json",
            results_dir / "tdx_wasm_latency_dcap_qvl_cold.json",
        ]
        if ensure_files(needed, args.strict, 28):
            mean, std = load_latency_pair(results_dir, "tdx", "latency_dcap_qvl_cold")
            axis_max = time_axis_max(mean, std, step=10.0)
            fig = build_paper_bars(
                tdx_labels,
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                "Time (ms)",
                axis_max=axis_max,
                separate=True,
            )
            save_figure(fig, "tdx_modified_dcap_latency_cold")

    # fig29 (latency modified tdx, warm)
    if to_generate["29"]:
        needed = [
            results_dir / "tdx_native_latency_dcap_qvl_hot.json",
            results_dir / "tdx_wasm_latency_dcap_qvl_hot.json",
        ]
        if ensure_files(needed, args.strict, 29):
            mean, std = load_latency_pair(results_dir, "tdx", "latency_dcap_qvl_hot")
            axis_max = time_axis_max(mean, std, step=10.0)
            fig = build_paper_bars(
                tdx_labels,
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                "Time (ms)",
                axis_max=axis_max,
                separate=True,
            )
            save_figure(fig, "tdx_modified_dcap_latency_hot")

    # fig30 (latency excluding collateral fetch)
    if to_generate["30"] and not suppress_standalone_30:
        needed = [
            results_dir / "tdx_native_latency_no_collateral.json",
            results_dir / "tdx_wasm_latency_no_collateral.json",
        ]
        if ensure_files(needed, args.strict, 30):
            mean, std = load_latency_pair(results_dir, "tdx", "latency_no_collateral")
            axis_max = time_axis_max(mean, std, step=10.0)
            fig = build_paper_bars(
                tdx_labels,
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                "Time (ms)",
                axis_max=axis_max,
                separate=True,
            )
            save_figure(fig, "tdx_latency_no_collateral")

    if generated == 0:
        print("[warn] no figures generated")
    return 0


def generate_evaluation_figures(args: argparse.Namespace) -> int:
    if args.paper:
        return generate_evaluation_figures_paper(args)
    results_dir = Path(args.results_dir)
    output_dir = Path(args.output_dir) if args.output_dir else results_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.output:
        raise SystemExit("--output is only valid for --preset onecol.")

    if matplotlib.__version__ != "3.10.3":
        print(f"[warn] matplotlib=={matplotlib.__version__} (original metadata was v3.10.3)")

    set_rcparams(args.font, args.titlefont, args.pdf_fonttype)
    show_values = not args.no_values
    show_titles = not args.separate
    savefig_kwargs = {"bbox_inches": "tight", "pad_inches": 0.02} if not args.separate else {}

    default_figs = list(range(21, 31))
    fig_numbers = args.figures if args.figures else default_figs
    for fig_number in fig_numbers:
        if fig_number < 21 or fig_number > 30:
            raise SystemExit("Evaluation preset supports figure numbers 21-30.")

    eval_index = 0
    generated = 0

    def save_eval(fig: plt.Figure, desc: str) -> None:
        nonlocal eval_index, generated
        eval_index += 1
        out_path = output_dir / f"eval{eval_index}_{desc}.{args.format}"
        fig.savefig(out_path, **savefig_kwargs)
        plt.close(fig)
        print(f"Wrote: {out_path}")
        generated += 1

    for fig_number in fig_numbers:
        fig = None
        desc = None
        if args.separate and args.figheight is None:
            fig_h = PAPER_FIGHEIGHT
        else:
            fig_h = evaluation_figheight(fig_number, args.figheight)
        use_default_width = abs(args.figwidth - DEFAULT_FIGWIDTH) < 1e-6
        split_panels = args.separate and fig_number in {21, 22, 24, 25, 27}
        if use_default_width:
            if args.separate:
                fig_w = PAPER_FIGWIDTH
            else:
                fig_w = DEFAULT_FIGWIDTH if fig_number in {23, 26, 28, 29, 30} else DEFAULT_EVAL_WIDE
        else:
            fig_w = args.figwidth

        if fig_number == 21:
            needed = [
                results_dir / "snp_native_latency.json",
                results_dir / "snp_wasm_latency.json",
                results_dir / "snp_native_verifier_time.json",
                results_dir / "snp_wasm_verifier_time.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            series = load_platform(results_dir, "snp")
            if args.separate:
                axis_max_e2e, axis_max_ver = latency_pair_axis_max(series, shared_axis_max=True)
                fig_a = build_single_latency(
                    "(a) AMD SEV-SNP\nEnd-to-End Attestation Latency (mean +/- std)",
                    series.e2e_mean,
                    series.e2e_std,
                    fig_w,
                    fig_h,
                    show_values,
                    show_title=show_titles,
                    axis_max=axis_max_e2e,
                    separate=args.separate,
                )
                save_eval(fig_a, "snp_latency_native_wasm")

                fig_b = build_single_latency(
                    "(b) AMD SEV-SNP\nVerification Time (mean +/- std)",
                    series.ver_mean,
                    series.ver_std,
                    fig_w,
                    fig_h,
                    show_values,
                    show_title=show_titles,
                    axis_max=axis_max_ver,
                    separate=args.separate,
                )
                save_eval(fig_b, "snp_verification_time_native_wasm")
                continue

            fig = build_latency_pair_twopanel(
                "AMD SEV-SNP",
                series,
                fig_w,
                fig_h,
                show_values,
                show_titles=show_titles,
                separate=args.separate,
            )
            desc = "snp_latency_verification_native_wasm"
        elif fig_number == 22:
            needed = [
                results_dir / "snp_native_step_breakdown.json",
                results_dir / "snp_wasm_step_breakdown.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            breakdown = load_breakdown(results_dir, "snp")
            if args.separate:
                fig_a = build_breakdown_panel(
                    breakdown,
                    fig_w,
                    fig_h,
                    show_values,
                    panel="native",
                    show_title=show_titles,
                    separate=args.separate,
                )
                save_eval(fig_a, "snp_verification_breakdown_native")

                fig_b = build_breakdown_panel(
                    breakdown,
                    fig_w,
                    fig_h,
                    show_values,
                    panel="wasm",
                    show_title=show_titles,
                    separate=args.separate,
                )
                save_eval(fig_b, "snp_verification_breakdown_wasm")
                continue

            fig = build_breakdown_twopanel(
                "AMD SEV-SNP",
                breakdown,
                fig_w,
                fig_h,
                show_values,
                show_titles=show_titles,
                separate=args.separate,
            )
            desc = "snp_verification_breakdown_native_wasm"
        elif fig_number == 23:
            needed = [
                results_dir / "snp_native_latency_no_cert.json",
                results_dir / "snp_wasm_latency_no_cert.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            mean, std = load_latency_pair(results_dir, "snp", "latency_no_cert")
            axis_max = None
            if show_values and not args.separate:
                raw_max = float(np.max(mean + std))
                axis_max = nice_limit(raw_max, pad=5.0, step=10.0)
                axis_max = max(axis_max, raw_max + max(raw_max * 0.35, 8.0))
            fig = build_single_latency(
                "End-to-end latency of an AMD SEV-SNP remote attestation request\nwithout certificate attached",
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                show_title=show_titles and False,
                separate=args.separate,
            )
            desc = "snp_no_cert_latency"
        elif fig_number == 24:
            needed = [
                results_dir / "snp_native_resources.json",
                results_dir / "snp_wasm_resources.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            resources = load_resources(results_dir, "snp")
            if args.separate:
                fig_a = build_resources_panel(
                    "AMD SEV-SNP",
                    resources,
                    fig_w,
                    fig_h,
                    show_values,
                    panel="rss",
                    show_title=show_titles,
                    separate=args.separate,
                )
                save_eval(fig_a, "snp_resources_rss")

                fig_b = build_resources_panel(
                    "AMD SEV-SNP",
                    resources,
                    fig_w,
                    fig_h,
                    show_values,
                    panel="cpu",
                    show_title=show_titles,
                    separate=args.separate,
                )
                save_eval(fig_b, "snp_resources_cpu")
                continue

            fig = build_resources_twopanel(
                "AMD SEV-SNP",
                resources,
                fig_w,
                fig_h,
                show_values,
                show_titles=show_titles,
                separate=args.separate,
            )
            desc = "snp_resources_rss_cpu"
        elif fig_number == 25:
            needed = [
                results_dir / "tdx_native_latency.json",
                results_dir / "tdx_wasm_latency.json",
                results_dir / "tdx_native_verifier_time.json",
                results_dir / "tdx_wasm_verifier_time.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            series = load_platform(results_dir, "tdx")
            if args.separate:
                axis_max_e2e, axis_max_ver = latency_pair_axis_max(series, shared_axis_max=False)
                fig_a = build_single_latency(
                    "(a) Intel TDX\nEnd-to-End Attestation Latency (mean +/- std)",
                    series.e2e_mean,
                    series.e2e_std,
                    fig_w,
                    fig_h,
                    show_values,
                    show_title=show_titles,
                    axis_max=axis_max_e2e,
                    separate=args.separate,
                )
                save_eval(fig_a, "tdx_latency_native_wasm")

                fig_b = build_single_latency(
                    "(b) Intel TDX\nVerification Time (mean +/- std)",
                    series.ver_mean,
                    series.ver_std,
                    fig_w,
                    fig_h,
                    show_values,
                    show_title=show_titles,
                    axis_max=axis_max_ver,
                    separate=args.separate,
                )
                save_eval(fig_b, "tdx_verification_time_native_wasm")
                continue

            fig = build_latency_pair_twopanel(
                "Intel TDX",
                series,
                fig_w,
                fig_h,
                show_values,
                shared_axis_max=False,
                show_titles=show_titles,
                separate=args.separate,
            )
            desc = "tdx_latency_verification_native_wasm"
        elif fig_number == 26:
            native_path = results_dir / "tdx_native_verifier_time_dcap_qvl.json"
            if not native_path.is_file():
                native_path = results_dir / "tdx_native_verifier_time.json"
            needed = [
                native_path,
                results_dir / "tdx_wasm_verifier_time.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            native = load_verifier_time(native_path)
            wasm = load_verifier_time(results_dir / "tdx_wasm_verifier_time.json")
            mean = np.array([native[0], wasm[0]], dtype=float)
            std = np.array([native[1], wasm[1]], dtype=float)
            fig = build_single_latency(
                "Verification latency of an Intel TDX remote attestation request",
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                show_title=show_titles and False,
                separate=args.separate,
            )
            desc = "tdx_modified_dcap_verification_time"
        elif fig_number == 27:
            needed = [
                results_dir / "tdx_native_resources.json",
                results_dir / "tdx_wasm_resources.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            resources = load_resources(results_dir, "tdx")
            if args.separate:
                fig_a = build_resources_panel(
                    "Intel TDX",
                    resources,
                    fig_w,
                    fig_h,
                    show_values,
                    panel="rss",
                    show_title=show_titles,
                    separate=args.separate,
                )
                save_eval(fig_a, "tdx_resources_rss")

                fig_b = build_resources_panel(
                    "Intel TDX",
                    resources,
                    fig_w,
                    fig_h,
                    show_values,
                    panel="cpu",
                    show_title=show_titles,
                    separate=args.separate,
                )
                save_eval(fig_b, "tdx_resources_cpu")
                continue

            fig = build_resources_twopanel(
                "Intel TDX",
                resources,
                fig_w,
                fig_h,
                show_values,
                show_titles=show_titles,
                separate=args.separate,
            )
            desc = "tdx_resources_rss_cpu"
        elif fig_number == 28:
            needed = [
                results_dir / "tdx_native_latency_dcap_qvl_cold.json",
                results_dir / "tdx_wasm_latency_dcap_qvl_cold.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            mean, std = load_latency_pair(results_dir, "tdx", "latency_dcap_qvl_cold")
            fig = build_single_latency(
                "End-to-end latency of an Intel TDX remote attestation request\n(dcap-qvl cache cold start)",
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                show_title=show_titles and False,
                separate=args.separate,
            )
            desc = "tdx_modified_dcap_latency_cold"
        elif fig_number == 29:
            needed = [
                results_dir / "tdx_native_latency_dcap_qvl_hot.json",
                results_dir / "tdx_wasm_latency_dcap_qvl_hot.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            mean, std = load_latency_pair(results_dir, "tdx", "latency_dcap_qvl_hot")
            fig = build_single_latency(
                "End-to-end latency of an Intel TDX remote attestation request\n(dcap-qvl cache hot start)",
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                show_title=show_titles and False,
                separate=args.separate,
            )
            desc = "tdx_modified_dcap_latency_hot"
        elif fig_number == 30:
            needed = [
                results_dir / "tdx_native_latency_no_collateral.json",
                results_dir / "tdx_wasm_latency_no_collateral.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            mean, std = load_latency_pair(results_dir, "tdx", "latency_no_collateral")
            fig = build_single_latency(
                "End-to-end latency of an Intel TDX remote attestation request\n(collateral fetch excluded)",
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                show_title=show_titles and False,
                separate=args.separate,
            )
            desc = "tdx_latency_no_collateral"

        if fig is not None and desc is not None:
            save_eval(fig, desc)

    if generated == 0:
        print("[warn] no figures generated")
    return 0


def generate_onecol_figures(args: argparse.Namespace) -> int:
    platforms = ["snp", "tdx"] if args.platform == "all" else [args.platform]
    styles = ["dumbbell", "bars"] if args.style == "all" else [args.style]

    if args.output and (len(platforms) != 1 or len(styles) != 1):
        raise SystemExit("--output requires a single --platform and --style.")

    results_dir = Path(args.results_dir)
    output_dir = Path(args.output_dir) if args.output_dir else results_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    if matplotlib.__version__ != "3.10.3":
        print(f"[warn] matplotlib=={matplotlib.__version__} (original metadata was v3.10.3)")

    layout_separate = args.separate or args.paper
    set_rcparams(args.font, args.titlefont, args.pdf_fonttype)
    show_titles = not layout_separate
    savefig_kwargs = {"bbox_inches": "tight", "pad_inches": 0.02} if not layout_separate else {}

    for platform in platforms:
        series = load_platform(results_dir, platform)
        platform_label = platform.upper()
        for style in styles:
            if layout_separate and args.figheight is None:
                fig_h = PAPER_FIGHEIGHT
            else:
                fig_h = args.figheight if args.figheight is not None else default_figheight(style)
            if style == "dumbbell":
                fig = build_dumbbell_onecol(
                    platform_label,
                    series,
                    args.figwidth,
                    fig_h,
                    show_values=not args.no_values,
                    show_title=show_titles,
                    separate=layout_separate,
                )
            else:
                fig = build_bars_breakdown_onecol(
                    platform_label, series, args.figwidth, fig_h,
                    show_values=not args.no_values,
                    show_title=show_titles and False,
                    separate=layout_separate,
                )

            if args.output:
                out_path = Path(args.output)
            else:
                out_path = output_dir / f"onecol_{platform}_{style}.{args.format}"

            fig.savefig(out_path, **savefig_kwargs)
            plt.close(fig)
            print(f"Wrote: {out_path}")
    return 0


def main() -> int:
    args = parse_args()
    if args.preset == "evaluation":
        return generate_evaluation_figures(args)
    if args.preset == "evaluation-all":
        status = generate_evaluation_figures(args)
        extra = argparse.Namespace(**vars(args))
        extra.preset = "onecol"
        extra.style = "bars"
        extra.platform = "all"
        generate_onecol_figures(extra)
        return status
    return generate_onecol_figures(args)


if __name__ == "__main__":
    raise SystemExit(main())
