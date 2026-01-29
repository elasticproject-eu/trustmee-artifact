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


def format_value(mean: float, std: float, layout: str = "inline") -> str:
    if layout == "stacked":
        return f"{mean:.2f}\n±{std:.2f}"
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
) -> None:
    x = np.arange(len(labels))
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
    if show_values:
        headroom = max(raw_max * 0.18, axis_max * 0.10, 1.2)
        axis_max = max(axis_max, raw_max + headroom)
    ax.set_ylim(0, axis_max)
    ax.grid(axis="y", linestyle="--", linewidth=1.0, alpha=0.6)
    ax.set_axisbelow(True)

    if show_values:
        offset = axis_max * pad_ratio * (0.7 if value_layout == "stacked" else 1.0)
        offset = max(offset, axis_max * 0.01)
        label_fs = max(
            plt.rcParams["font.size"] - (2.2 if value_layout == "stacked" else 1.5),
            6.5,
        )
        for xi, m, s in zip(x, mean, std):
            label = format_value(m, s, layout=value_layout)
            y = min(m + s + offset, axis_max - max(headroom * 0.35, offset * 0.6))
            ax.text(
                xi,
                y,
                label,
                ha="center",
                va="bottom",
                fontsize=label_fs,
            )


def build_latency_pair_twopanel(
    platform_label: str,
    series: LatencySeries,
    fig_w: float,
    fig_h: float,
    show_values: bool,
) -> plt.Figure:
    labels = ["native\nTrustee AS", "Wasm-based\nAS"]
    colors = ["#81c784", "#63b5f6"]

    axis_max = nice_limit(float(max(
        np.max(series.e2e_mean + series.e2e_std),
        np.max(series.ver_mean + series.ver_std),
    )))

    fig, axes = plt.subplots(ncols=2, figsize=(fig_w, fig_h), dpi=300)
    fig.subplots_adjust(left=0.10, right=0.98, top=0.86, bottom=0.22, wspace=0.38)

    bar_compare(
        axes[0],
        labels,
        series.e2e_mean,
        series.e2e_std,
        colors,
        "Time (ms)",
        f"(a) {platform_label}\nEnd-to-End Attestation Latency (mean +/- std)",
        show_values,
        axis_max=axis_max,
    )
    bar_compare(
        axes[1],
        labels,
        series.ver_mean,
        series.ver_std,
        colors,
        "Time (ms)",
        f"(b) {platform_label}\nVerification Time (mean +/- std)",
        show_values,
        axis_max=axis_max,
    )
    return fig


def build_breakdown_twopanel(
    platform_label: str,
    breakdown: BreakdownSeries,
    fig_w: float,
    fig_h: float,
    show_values: bool,
) -> plt.Figure:
    colors = ["#63b5f6", "#81c784"]
    axis_max = nice_limit(float(max(
        np.max(breakdown.wasm_mean + breakdown.wasm_std),
        np.max(breakdown.native_mean + breakdown.native_std),
    )), pad=2.0, step=2.0)

    fig, axes = plt.subplots(ncols=2, figsize=(fig_w, fig_h), dpi=300)
    fig.subplots_adjust(left=0.10, right=0.98, top=0.86, bottom=0.22, wspace=0.38)

    bar_compare(
        axes[0],
        breakdown.labels,
        breakdown.wasm_mean,
        breakdown.wasm_std,
        [colors[0]] * len(breakdown.labels),
        "Time (ms)",
        "(a) Wasm Verification Time",
        show_values,
        axis_max=axis_max,
        pad_ratio=0.03,
        value_layout="stacked",
    )
    axes[0].tick_params(axis="x", labelsize=max(plt.rcParams["font.size"] - 2.2, 6.2), pad=2)
    bar_compare(
        axes[1],
        breakdown.labels,
        breakdown.native_mean,
        breakdown.native_std,
        [colors[1]] * len(breakdown.labels),
        "Time (ms)",
        "(b) Native Verification Time",
        show_values,
        axis_max=axis_max,
        pad_ratio=0.03,
        value_layout="stacked",
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
) -> plt.Figure:
    labels = ["native\nTrustee AS", "Wasm-based\nAS"]
    colors = ["#81c784", "#63b5f6"]

    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=300)
    fig.subplots_adjust(left=0.18, right=0.98, top=0.94, bottom=0.18)
    bar_compare(
        ax,
        labels,
        mean,
        std,
        colors,
        "Time (ms)",
        title if show_title else None,
        show_values,
        axis_max=nice_limit(float(np.max(mean + std)), pad=5.0, step=10.0),
    )
    return fig


def build_resources_twopanel(
    platform_label: str,
    resources: ResourceSeries,
    fig_w: float,
    fig_h: float,
    show_values: bool,
) -> plt.Figure:
    labels = ["native\nTrustee AS", "Wasm-based\nAS"]
    colors = ["#81c784", "#63b5f6"]

    fig, axes = plt.subplots(ncols=2, figsize=(fig_w, fig_h), dpi=300)
    fig.subplots_adjust(left=0.10, right=0.98, top=0.86, bottom=0.22, wspace=0.38)

    rss_mean_mb = resources.rss_mean / 1024.0
    rss_std_mb = resources.rss_std / 1024.0
    bar_compare(
        axes[0],
        labels,
        rss_mean_mb,
        rss_std_mb,
        colors,
        "RSS (MB)",
        f"(a) {platform_label}\nRSS usage during attestation",
        show_values,
        axis_max=nice_limit(float(np.max(rss_mean_mb + rss_std_mb)), pad=2.0, step=10.0),
        pad_ratio=0.02,
    )
    bar_compare(
        axes[1],
        labels,
        resources.cpu_mean,
        resources.cpu_std,
        colors,
        "CPU (%)",
        f"(b) {platform_label}\nCPU usage during attestation",
        show_values,
        axis_max=nice_limit(float(np.max(resources.cpu_mean + resources.cpu_std)), pad=0.4, step=1.0),
        pad_ratio=0.08,
    )
    return fig


def build_dumbbell_onecol(
    platform: str,
    series: LatencySeries,
    fig_w: float,
    fig_h: float,
    show_values: bool,
) -> plt.Figure:
    green = "#81c784"
    blue = "#63b5f6"

    metrics = ["E2E latency", "Verify time"]
    native_mean = np.array([series.e2e_mean[0], series.ver_mean[0]], dtype=float)
    native_std = np.array([series.e2e_std[0], series.ver_std[0]], dtype=float)
    wasm_mean = np.array([series.e2e_mean[1], series.ver_mean[1]], dtype=float)
    wasm_std = np.array([series.e2e_std[1], series.ver_std[1]], dtype=float)

    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=300)
    fig.subplots_adjust(left=0.33, right=0.98, top=0.82, bottom=0.34)

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
    ax.set_title(f"{platform} latency (mean +/- std)", pad=10)

    if show_values:
        for i in range(len(metrics)):
            yi = y[i]
            if yi == y.max():
                ax.annotate(
                    format_value(native_mean[i], native_std[i]),
                    (native_mean[i], yi),
                    xytext=(6, -10), textcoords="offset points",
                    ha="left", va="top", fontsize=9.2,
                )
                ax.annotate(
                    format_value(wasm_mean[i], wasm_std[i]),
                    (wasm_mean[i], yi),
                    xytext=(-6, 8), textcoords="offset points",
                    ha="right", va="bottom", fontsize=9.2,
                )
            else:
                ax.annotate(
                    format_value(native_mean[i], native_std[i]),
                    (native_mean[i], yi),
                    xytext=(6, 8), textcoords="offset points",
                    ha="left", va="bottom", fontsize=9.2,
                )
                ax.annotate(
                    format_value(wasm_mean[i], wasm_std[i]),
                    (wasm_mean[i], yi),
                    xytext=(-6, -10), textcoords="offset points",
                    ha="right", va="top", fontsize=9.2,
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
    fig.subplots_adjust(left=0.20, right=0.98, top=0.88, bottom=0.30)

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
        fs_total = max(base - 1.8, 7.0)
        fs_ver = max(base - 2.8, 6.4)

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
    return ap.parse_args()


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


def generate_evaluation_figures(args: argparse.Namespace) -> int:
    results_dir = Path(args.results_dir)
    output_dir = Path(args.output_dir) if args.output_dir else results_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.output:
        raise SystemExit("--output is only valid for --preset onecol.")

    if matplotlib.__version__ != "3.10.3":
        print(f"[warn] matplotlib=={matplotlib.__version__} (original metadata was v3.10.3)")

    set_rcparams(args.font, args.titlefont, args.pdf_fonttype)
    show_values = not args.no_values

    default_figs = list(range(21, 28))
    fig_numbers = args.figures if args.figures else default_figs
    for fig_number in fig_numbers:
        if fig_number < 21 or fig_number > 27:
            raise SystemExit("Evaluation preset supports figure numbers 21-27.")

    generated = 0

    for fig_number in fig_numbers:
        fig = None
        out_path = None
        fig_h = evaluation_figheight(fig_number, args.figheight)
        use_default_width = abs(args.figwidth - DEFAULT_FIGWIDTH) < 1e-6
        if use_default_width:
            fig_w = DEFAULT_FIGWIDTH if fig_number in {23, 26} else DEFAULT_EVAL_WIDE
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
            fig = build_latency_pair_twopanel("AMD SEV-SNP", series, fig_w, fig_h, show_values)
            out_path = output_dir / f"fig21_snp_latency_verification.{args.format}"
        elif fig_number == 22:
            needed = [
                results_dir / "snp_native_step_breakdown.json",
                results_dir / "snp_wasm_step_breakdown.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            breakdown = load_breakdown(results_dir, "snp")
            fig = build_breakdown_twopanel("AMD SEV-SNP", breakdown, fig_w, fig_h, show_values)
            out_path = output_dir / f"fig22_snp_verification_breakdown.{args.format}"
        elif fig_number == 23:
            needed = [
                results_dir / "snp_native_latency_no_cert.json",
                results_dir / "snp_wasm_latency_no_cert.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            mean, std = load_latency_pair(results_dir, "snp", "latency_no_cert")
            fig = build_single_latency(
                "End-to-end latency of an AMD SEV-SNP remote attestation request\nwithout certificate attached",
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                show_title=False,
            )
            out_path = output_dir / f"fig23_snp_latency_no_cert.{args.format}"
        elif fig_number == 24:
            needed = [
                results_dir / "snp_native_resources.json",
                results_dir / "snp_wasm_resources.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            resources = load_resources(results_dir, "snp")
            fig = build_resources_twopanel("SNP", resources, fig_w, fig_h, show_values)
            out_path = output_dir / f"fig24_snp_resources.{args.format}"
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
            fig = build_latency_pair_twopanel("Intel TDX", series, fig_w, fig_h, show_values)
            out_path = output_dir / f"fig25_tdx_latency_verification.{args.format}"
        elif fig_number == 26:
            needed = [
                results_dir / "tdx_native_verifier_time.json",
                results_dir / "tdx_wasm_verifier_time.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            mean, std = load_verifier_pair(results_dir, "tdx")
            fig = build_single_latency(
                "Verification latency of an Intel TDX remote attestation request",
                mean,
                std,
                fig_w,
                fig_h,
                show_values,
                show_title=False,
            )
            out_path = output_dir / f"fig26_tdx_remote_verification.{args.format}"
        elif fig_number == 27:
            needed = [
                results_dir / "tdx_native_resources.json",
                results_dir / "tdx_wasm_resources.json",
            ]
            if not ensure_files(needed, args.strict, fig_number):
                continue
            resources = load_resources(results_dir, "tdx")
            fig = build_resources_twopanel("TDX", resources, fig_w, fig_h, show_values)
            out_path = output_dir / f"fig27_tdx_resources.{args.format}"

        if fig is not None and out_path is not None:
            fig.savefig(out_path, bbox_inches="tight", pad_inches=0.02)
            plt.close(fig)
            print(f"Wrote: {out_path}")
            generated += 1

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

    set_rcparams(args.font, args.titlefont, args.pdf_fonttype)

    for platform in platforms:
        series = load_platform(results_dir, platform)
        platform_label = platform.upper()
        for style in styles:
            fig_h = args.figheight if args.figheight is not None else default_figheight(style)
            if style == "dumbbell":
                fig = build_dumbbell_onecol(
                    platform_label, series, args.figwidth, fig_h,
                    show_values=not args.no_values,
                )
            else:
                fig = build_bars_breakdown_onecol(
                    platform_label, series, args.figwidth, fig_h,
                    show_values=not args.no_values,
                    show_title=False,
                )

            if args.output:
                out_path = Path(args.output)
            else:
                out_path = output_dir / f"onecol_{platform}_{style}.{args.format}"

            fig.savefig(out_path, bbox_inches="tight", pad_inches=0.02)
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
