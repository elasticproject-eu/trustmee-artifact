#!/usr/bin/env python3
"""Generate the selected PDFs for the paper evaluation.

Reads the JSON summaries written by `run_all.sh` out of `--results-dir` and
emits the requested PDFs into `--output-dir`. Color conventions:
  * SNP bars/segments → green shades
  * TDX bars/segments → blue shades
  * SGX bars/segments → orange shades
  * Stacked segments within a bar use hatches + lighter/darker shades.
No figure carries an on-plot title.
"""

from __future__ import annotations

import argparse
import json
import math
from collections.abc import Callable
from pathlib import Path

import matplotlib
import matplotlib.patheffects as path_effects

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.transforms import Bbox
import numpy as np


# Default canvas size for generated PDFs.
# Do not use bbox_inches="tight" in savefig, otherwise PDFs may differ in size.
FIG_SIZE = (5.4, 4.6)
FIG_DPI = 150


matplotlib.rcParams.update({
    "font.size":        14,
    "axes.labelsize":   16,
    "axes.titlesize":   16,
    "xtick.labelsize":  14,
    "ytick.labelsize":  14,
    "legend.fontsize":  12,
    "figure.titlesize": 16,
})

# Keep annotations consistent with the other figures.
ANNOT_FONTSIZE       = 13
ANNOT_TOTAL_FONTSIZE = 13

COMPARISON_XTICK_FONTSIZE = 12
COMPARISON_VALUE_FONTSIZE = 13
COMPARISON_SEGMENT_FONTSIZE = 11
COMPARISON_LEGEND_FONTSIZE = 12
COMPARISON_BAR_FIG_SIZE = (6.2, 4.8)
COMPARISON_BAR_ADJUST = {
    "left": 0.12,
    "right": 0.98,
    "top": 0.94,
    "bottom": 0.35,
}
CROWDED_XTICK_ROTATION = 45
CROWDED_XTICK_FONTSIZE = 11
CROWDED_BAR_ADJUST = {
    "left": 0.12,
    "right": 0.98,
    "top": 0.94,
    "bottom": 0.37,
}
VERTICAL_ONLY_CROPS_IN = {
    "eval1_e2e_no_collateral_hot_plus_verifiers.pdf": (0.22, 0.20),
    "eval1_e2e_no_collateral_hot_plus_verifiers_with_sgx.pdf": (0.12, 0.20),
    "eval3_cold_vs_hot_merged.pdf": (0.20, 0.20),
    "eval3_cold_vs_hot_4bar_merged.pdf": (0.20, 0.20),
    "eval7_e2e_with_collateral.pdf": (0.32, 0.20),
}

# Canonical palette: one hue per platform.
PLATFORMS = ("snp", "tdx")
SNP_COLOR = "#81c784"
SNP_ALT_COLOR = "#2e7d32"
TDX_COLOR = "#63b5f6"
TDX_ALT_COLOR = "#0d47a1"
SGX_COLOR = "#ffb74d"
SGX_ALT_COLOR = "#ef6c00"
PLATFORM_COLOR = {
    "snp": SNP_COLOR,
    "tdx": TDX_COLOR,
}
PLATFORM_ALT_COLOR = {
    "snp": SNP_ALT_COLOR,
    "tdx": TDX_ALT_COLOR,
}

# Shade ramps for stacked bars.
SNP_STACK = ["#1b5e20", "#4caf50", "#a5d6a7", "#e8f5e9"]
TDX_STACK = ["#0d47a1", "#42a5f5", "#bbdefb", "#e3f2fd"]
STACK_HATCHES = ["////", "xxxx", "....", ""]
EVAL3_STACK_COLORS = {
    "snp": [SNP_STACK[0], SNP_COLOR, SNP_COLOR],
    "tdx": [TDX_STACK[0], TDX_COLOR, TDX_COLOR],
}
EVAL3_STACK_HATCHES = [STACK_HATCHES[0], STACK_HATCHES[2], STACK_HATCHES[1]]
EVAL4_SEG_NAMES = ["cert chain", "signature", "other"]
BOLD_PLATFORM_LABELS = frozenset(("SNP", "TDX"))


def read_summary(path: Path) -> tuple[float, float]:
    data = json.loads(path.read_text())
    return float(data.get("mean_ms", 0.0)), float(data.get("std_ms", 0.0))


def read_timing(path: Path) -> tuple[float, float]:
    data = json.loads(path.read_text())
    sub = data.get("ms", {})
    return float(sub.get("mean", 0.0)), float(sub.get("std", 0.0))


def read_breakdown(path: Path) -> dict:
    return json.loads(path.read_text())


def load_bar_data(
    results: Path,
    series: list[tuple[str, Callable[[Path], tuple[float, float]], str, str]],
    skip_name: str,
) -> tuple[list[str], list[float], list[float], list[str]] | None:
    labels, means, stds, colors = [], [], [], []

    for filename, reader, label, color in series:
        path = results / filename

        if not path.is_file():
            print(f"[warn] missing {path}; skipping {skip_name}")
            return None

        mean, std = reader(path)
        labels.append(label)
        means.append(mean)
        stds.append(std)
        colors.append(color)

    return labels, means, stds, colors


def bold_platform_prefixes(
    labels: list[str],
    platforms: frozenset[str] = BOLD_PLATFORM_LABELS,
) -> list[str]:
    formatted = []

    for label in labels:
        for platform in platforms:
            if label.startswith(platform) and (
                len(label) == len(platform) or label[len(platform)] in (" ", "\n")
            ):
                formatted.append(rf"$\bf{{{platform}}}$" + label[len(platform):])
                break
        else:
            formatted.append(label)

    return formatted


def nice_limit(raw_max: float, pad: float = 5.0, step: float = 10.0) -> float:
    limit = raw_max + pad
    return max(step * 2.0, math.ceil(limit / step) * step)


def save_pdf(fig, out_path: Path) -> None:
    """Save a PDF, optionally cropping only its vertical whitespace.

    The crop keeps the full original figure width, so including the output in
    LaTeX at a fixed width preserves the internal text and axis scale.
    """
    crop = VERTICAL_ONLY_CROPS_IN.get(out_path.name)

    if crop is None:
        fig.savefig(out_path)
        return

    bottom_crop, top_crop = crop
    width, height = fig.get_size_inches()
    bbox = Bbox.from_extents(0, bottom_crop, width, height - top_crop)
    fig.savefig(out_path, bbox_inches=bbox)


# ---------------------- plot primitives -------------------------------------


def plain_bar(
    labels: list[str],
    means: list[float],
    stds: list[float],
    colors: list[str],
    out_path: Path,
    fig_size: tuple[float, float] = FIG_SIZE,
    xtick_rotation: float = 0.0,
    xtick_ha: str = "center",
    xtick_fontsize: float | None = None,
    subplot_adjust: dict[str, float] | None = None,
    bold_platform_xtick_prefixes: bool = False,
) -> None:
    fig, ax = plt.subplots(figsize=fig_size, dpi=FIG_DPI)
    x = np.arange(len(labels))

    ax.bar(
        x,
        means,
        width=0.55,
        yerr=stds,
        color=colors,
        edgecolor="black",
        linewidth=0.6,
        capsize=4.0,
        error_kw={"elinewidth": 1.2, "capthick": 1.2},
    )

    ax.set_xticks(x)
    xtick_labels = (
        bold_platform_prefixes(labels) if bold_platform_xtick_prefixes else labels
    )

    if xtick_rotation:
        ax.set_xticklabels(
            xtick_labels,
            rotation=xtick_rotation,
            ha=xtick_ha,
            rotation_mode="anchor",
            fontsize=xtick_fontsize,
        )
    else:
        ax.set_xticklabels(xtick_labels, fontsize=xtick_fontsize)
    ax.set_ylabel("Time (ms)")

    ax.grid(axis="y", linestyle="--", linewidth=0.8, alpha=0.55)
    ax.set_axisbelow(True)

    max_top = max(m + s for m, s in zip(means, stds)) if means else 1.0
    ax.set_ylim(0, nice_limit(max_top, pad=max_top * 0.22 + 1.0, step=10.0))

    for xi, m, s in zip(x, means, stds):
        ax.annotate(
            f"{m:.1f}\n±{s:.1f}",
            xy=(xi, m + s),
            xytext=(0, 5),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=ANNOT_FONTSIZE,
        )

    if subplot_adjust is not None:
        fig.subplots_adjust(**subplot_adjust)
    else:
        fig.tight_layout()

    save_pdf(fig, out_path)
    plt.close(fig)
    print(f"wrote {out_path}")


def _fig3_eval2_cold_breakdown(
    results: Path,
    platform: str,
) -> tuple[list[float], float]:
    path = results / f"eval2_{platform}_wasm_breakdown.json"

    if not path.is_file():
        raise FileNotFoundError(path)

    data = read_breakdown(path)
    load_inst = float(data["load"]["mean"]) + float(data["instantiate"]["mean"])
    verify = float(data["verify"]["mean"])
    other = float(data.get("other_mean", 0.0))

    if other <= 0.0 and "as_verifier" in data:
        asv_mean = float(data["as_verifier"].get("mean", 0.0))
        other = max(asv_mean - (load_inst + verify), 0.0)

    total_std = float(data.get("as_verifier", data.get("total", {})).get("std", 0.0))
    return [load_inst, verify, other], total_std


def _fig3_metric(
    results: Path,
    platform: str,
    state: str,
) -> tuple[float, float]:
    return read_summary(results / f"eval3_{platform}_wasm_latency_{state}.json")


def merged_cold_start_chart(
    results: Path,
    out_path: Path,
    states: list[str],
    bold_platform_xtick_prefixes: bool = False,
) -> None:
    """Eval3 chart where cold bars use eval2's load/verify breakdown."""
    labels = [
        f"{platform.upper()}\nWasm-based\n{state}"
        for platform in PLATFORMS
        for state in states
    ]
    try:
        bars = []

        for platform in PLATFORMS:
            for state in states:
                if state == "cold":
                    segments, std = _fig3_eval2_cold_breakdown(results, platform)
                    bars.append(
                        {
                            "segments": segments,
                            "std": std,
                            "colors": EVAL3_STACK_COLORS[platform],
                            "hatches": EVAL3_STACK_HATCHES,
                            "platform": platform,
                        }
                    )
                else:
                    mean, std = _fig3_metric(results, platform, state)
                    bars.append(
                        {
                            "segments": [mean],
                            "std": std,
                            "colors": [
                                PLATFORM_COLOR[platform]
                                if state == "warm"
                                else PLATFORM_ALT_COLOR[platform]
                            ],
                            "hatches": [None],
                            "platform": platform,
                        }
                    )
    except FileNotFoundError as e:
        missing = e.filename or (e.args[0] if e.args else "<unknown>")
        print(f"[warn] missing {missing}; skipping {out_path.name}")
        return

    fig, ax = plt.subplots(figsize=COMPARISON_BAR_FIG_SIZE, dpi=FIG_DPI)
    x = np.arange(len(labels))
    bar_width = 0.50
    max_top = 0.0

    for xi, spec in zip(x, bars):
        bottom = 0.0

        for val, color, hatch in zip(spec["segments"], spec["colors"], spec["hatches"]):
            ax.bar(
                xi,
                val,
                bottom=bottom,
                width=bar_width,
                color=color,
                edgecolor="black",
                linewidth=0.6,
                hatch=hatch,
            )
            bottom += float(val)

        total = sum(float(v) for v in spec["segments"])
        std = float(spec["std"])
        max_top = max(max_top, total + std)

        if std > 0:
            ax.errorbar(
                xi,
                total,
                yerr=std,
                fmt="none",
                ecolor="black",
                elinewidth=1.2,
                capthick=1.2,
                capsize=4.0,
            )

    ymax = nice_limit(max_top, pad=max_top * 0.20 + 1.0, step=10.0)
    ax.set_ylim(0, ymax)

    for xi, spec in zip(x, bars):
        total = sum(float(v) for v in spec["segments"])
        std = float(spec["std"])
        is_stacked = len(spec["segments"]) > 1

        if is_stacked:
            running = 0.0

            for idx, val in enumerate(spec["segments"]):
                val = float(val)
                if val <= 0:
                    running += val
                    continue

                if idx == len(spec["segments"]) - 1:
                    side = -1 if spec["platform"] == "tdx" else 1
                    ax.annotate(
                        f"{val:.1f}",
                        xy=(
                            xi + side * (bar_width / 2 + 0.06),
                            running + val / 2.0,
                        ),
                        ha="right" if side < 0 else "left",
                        va="center",
                        fontsize=COMPARISON_SEGMENT_FONTSIZE,
                        color="black",
                    )
                    running += val
                    continue

                ax.annotate(
                    f"{val:.1f}",
                    xy=(xi, running + val / 2.0),
                    ha="center",
                    va="center",
                    fontsize=COMPARISON_SEGMENT_FONTSIZE,
                    color="white",
                    path_effects=[
                        path_effects.Stroke(linewidth=1.3, foreground="black"),
                        path_effects.Normal(),
                    ],
                )
                running += val

        ax.annotate(
            f"{total:.1f}\n+/-{std:.1f}",
            xy=(xi, total + std),
            xytext=(0, 5),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=ANNOT_TOTAL_FONTSIZE if is_stacked else ANNOT_FONTSIZE,
        )

    ax.set_xticks(x)
    ax.set_xticklabels(
        bold_platform_prefixes(labels) if bold_platform_xtick_prefixes else labels,
        rotation=CROWDED_XTICK_ROTATION,
        ha="right",
        rotation_mode="anchor",
        fontsize=CROWDED_XTICK_FONTSIZE,
    )
    ax.set_ylabel("Time (ms)")
    ax.set_xlim(x[0] - 0.6, x[-1] + 0.8)
    ax.grid(axis="y", linestyle="--", linewidth=0.8, alpha=0.55)
    ax.set_axisbelow(True)

    handles = [
        Patch(
            facecolor="white",
            edgecolor="black",
            linewidth=0.6,
            hatch=hatch,
            label=label,
        )
        for hatch, label in zip(
            EVAL3_STACK_HATCHES,
            ["Load + instantiate", "Verify", "AS overhead"],
        )
    ]

    fig.legend(
        handles=handles,
        loc="lower center",
        bbox_to_anchor=(0.5, 0.04),
        ncol=3,
        frameon=False,
        fontsize=COMPARISON_LEGEND_FONTSIZE,
        handletextpad=0.6,
        columnspacing=1.0,
    )

    fig.subplots_adjust(**CROWDED_BAR_ADJUST)

    save_pdf(fig, out_path)
    plt.close(fig)
    print(f"wrote {out_path}")


# ---------------------- figures ----------------------------------------------


def fig1_hot_plus_verifiers(results: Path, out: Path) -> None:
    data = load_bar_data(
        results,
        [
            (
                "eval1_snp_native_latency.json",
                read_summary,
                "SNP Native",
                SNP_COLOR,
            ),
            (
                "eval1_snp_wasm_latency_hot.json",
                read_summary,
                "SNP Wasm-based",
                SNP_COLOR,
            ),
            (
                "eval5_snp_host_crypto_latency.json",
                read_summary,
                "SNP Wasm-based\nhost-crypto",
                SNP_ALT_COLOR,
            ),
            (
                "eval1_tdx_native_latency.json",
                read_summary,
                "TDX Native\nIntel DCAP-QVL",
                TDX_ALT_COLOR,
            ),
            (
                "eval6_tdx_native_verifier_dcap_qvl.json",
                read_timing,
                "TDX Native\npure-rust DCAP-QVL",
                TDX_COLOR,
            ),
            (
                "eval1_tdx_wasm_latency_hot.json",
                read_summary,
                "TDX Wasm-based\npure-rust DCAP-QVL",
                TDX_COLOR,
            ),
        ],
        "eval1 hot verifier comparison",
    )

    if data is None:
        return

    labels, means, stds, colors = data

    plain_bar(
        labels,
        means,
        stds,
        colors,
        out / "eval1_e2e_no_collateral_hot_plus_verifiers.pdf",
        fig_size=COMPARISON_BAR_FIG_SIZE,
        xtick_rotation=CROWDED_XTICK_ROTATION,
        xtick_ha="right",
        xtick_fontsize=CROWDED_XTICK_FONTSIZE,
        subplot_adjust=CROWDED_BAR_ADJUST,
    )


def fig1_hot_plus_verifiers_with_sgx(results: Path, out: Path) -> None:
    data = load_bar_data(
        results,
        [
            (
                "eval1_snp_native_latency.json",
                read_summary,
                "SNP Native",
                SNP_COLOR,
            ),
            (
                "eval1_snp_wasm_latency_hot.json",
                read_summary,
                "SNP Wasm-based",
                SNP_COLOR,
            ),
            (
                "eval5_snp_host_crypto_latency.json",
                read_summary,
                "SNP Wasm-based\nhost-crypto",
                SNP_ALT_COLOR,
            ),
            (
                "eval1_tdx_native_latency.json",
                read_summary,
                "TDX Native\nIntel DCAP-QVL",
                TDX_ALT_COLOR,
            ),
            (
                "eval6_tdx_native_verifier_dcap_qvl.json",
                read_timing,
                "TDX Native\npure-rust DCAP-QVL",
                TDX_COLOR,
            ),
            (
                "eval1_tdx_wasm_latency_hot.json",
                read_summary,
                "TDX Wasm-based\npure-rust DCAP-QVL",
                TDX_COLOR,
            ),
            (
                "eval1_sgx_native_latency.json",
                read_summary,
                "SGX Native\nIntel DCAP-QVL",
                SGX_ALT_COLOR,
            ),
            (
                "eval1_sgx_native_verifier_dcap_qvl.json",
                read_timing,
                "SGX Native\npure-rust DCAP-QVL",
                SGX_COLOR,
            ),
            (
                "eval1_sgx_wasm_latency_hot.json",
                read_summary,
                "SGX Wasm-based\npure-rust DCAP-QVL",
                SGX_COLOR,
            ),
        ],
        "eval1 hot verifier comparison with SGX",
    )

    if data is None:
        return

    labels, means, stds, colors = data

    plain_bar(
        labels,
        means,
        stds,
        colors,
        out / "eval1_e2e_no_collateral_hot_plus_verifiers_with_sgx.pdf",
        fig_size=COMPARISON_BAR_FIG_SIZE,
        xtick_rotation=CROWDED_XTICK_ROTATION,
        xtick_ha="right",
        xtick_fontsize=CROWDED_XTICK_FONTSIZE,
        subplot_adjust=CROWDED_BAR_ADJUST,
        bold_platform_xtick_prefixes=True,
    )


def fig3_merged(results: Path, out: Path, more_detail: bool = False) -> None:
    figures = []

    if more_detail:
        figures.append(
            (
                "eval3_cold_vs_hot_merged.pdf",
                ["cold", "warm", "hot"],
            )
        )

    figures.append(
        (
            "eval3_cold_vs_hot_4bar_merged.pdf",
            ["cold", "warm"],
        ),
    )

    for filename, states in figures:
        merged_cold_start_chart(
            results,
            out / filename,
            states,
            bold_platform_xtick_prefixes=filename == "eval3_cold_vs_hot_4bar_merged.pdf",
        )


def fig4_pie_only(results: Path, out: Path) -> None:
    required = [
        results / f"eval4_snp_{mode}_step_breakdown.json"
        for mode in ["native", "wasm"]
    ]

    if any(not path.is_file() for path in required):
        print("[warn] eval4 inputs missing; skipping fig4 pie")
        return

    native_seg = eval4_segments(results, "native")
    wasm_seg = eval4_segments(results, "wasm")

    if native_seg is None or wasm_seg is None:
        print("[warn] eval4 inputs contain no usable samples; skipping fig4 pie")
        return

    fig4_pie(native_seg, wasm_seg, out / "eval4_snp_step_breakdown_pie.pdf")


def _summary_count(data: dict, field: str) -> int:
    sub = data.get(field, {})
    if not isinstance(sub, dict):
        return 0
    return int(sub.get("count", 0))


def _summary_mean(data: dict, field: str) -> float:
    sub = data.get(field, {})
    if not isinstance(sub, dict):
        return 0.0
    return float(sub.get("mean", 0.0))


def eval4_segments(results: Path, mode: str) -> np.ndarray | None:
    step = read_breakdown(results / f"eval4_snp_{mode}_step_breakdown.json")
    if (
        _summary_count(step, "cert_chain_ms") <= 0
        or _summary_count(step, "signature_ms") <= 0
        or _summary_count(step, "others_ms") <= 0
    ):
        return None

    cert = _summary_mean(step, "cert_chain_ms")
    signature = _summary_mean(step, "signature_ms")
    other = _summary_mean(step, "others_ms")
    segments = np.array([cert, signature, other], dtype=float)
    if not np.all(np.isfinite(segments)) or float(np.sum(segments)) <= 0.0:
        return None

    return segments


def fig4_pie(
    native_seg: np.ndarray,
    wasm_seg: np.ndarray,
    out_path: Path,
) -> None:
    fig, (ax_n, ax_w) = plt.subplots(ncols=2, figsize=(5.4, 3.8), dpi=FIG_DPI)

    def annotate_values(ax, wedges, values: np.ndarray) -> None:
        # Place every label on the same circle, just outside the pie. The
        # ha/va anchors are chosen so the text always grows away from the
        # pie center, keeping a uniform gap on top, bottom and sides.
        label_radius = 1.15

        for wedge, value in zip(wedges, values):
            theta = math.radians((wedge.theta1 + wedge.theta2) / 2.0)
            x_dir = math.cos(theta)
            y_dir = math.sin(theta)

            x = label_radius * x_dir
            y = label_radius * y_dir

            ax.text(
                x,
                y,
                f"{float(value):.2f} ms",
                ha="left" if x_dir > 0.15 else "right" if x_dir < -0.15 else "center",
                va="bottom" if y_dir > 0.15 else "top" if y_dir < -0.15 else "center",
                fontsize=COMPARISON_VALUE_FONTSIZE,
            )

    for ax, values, label, colors in [
        (ax_n, native_seg, "Native", SNP_STACK),
        (ax_w, wasm_seg, "Wasm", SNP_STACK),
    ]:
        wedges, _texts = ax.pie(
            values,
            colors=colors[: len(values)],
            startangle=90,
            counterclock=False,
            radius=1.08,
            wedgeprops={"edgecolor": "black", "linewidth": 0.6},
        )

        for wedge, hatch in zip(wedges, STACK_HATCHES):
            wedge.set_hatch(hatch)

        annotate_values(ax, wedges, values)

        ax.set_aspect("equal")
        ax.set_xlabel(label)
        ax.xaxis.set_label_coords(0.5, -0.14)
        ax.set_xlim(-1.95, 1.95)
        ax.set_ylim(-1.45, 1.40)

    legend_handles = [
        Patch(
            facecolor=SNP_STACK[i],
            edgecolor="black",
            linewidth=0.6,
            hatch=STACK_HATCHES[i],
            label=seg_name,
        )
        for i, seg_name in enumerate(EVAL4_SEG_NAMES)
    ]

    # Keep the pie legend closer to the charts by using less bottom margin.
    fig.legend(
        handles=legend_handles,
        loc="lower center",
        bbox_to_anchor=(0.5, 0.1),
        ncol=3,
        frameon=False,
        fontsize=COMPARISON_LEGEND_FONTSIZE,
        handletextpad=0.6,
        columnspacing=1.0,
    )

    fig.subplots_adjust(
        left=0.02,
        right=0.98,
        top=0.98,
        bottom=0.19,
        wspace=0.35,
    )

    fig.savefig(out_path, bbox_inches="tight", pad_inches=0.03)
    plt.close(fig)
    print(f"wrote {out_path}")


def fig7(results: Path, out: Path) -> None:
    data = load_bar_data(
        results,
        [
            (
                f"eval7_{platform}_{mode}_latency.json",
                read_summary,
                f"{platform.upper()}\n{'native' if mode == 'native' else 'Wasm-based'}",
                color,
            )
            for platform, mode, color in [
                ("snp", "native", SNP_COLOR),
                ("snp", "wasm", SNP_COLOR),
                ("tdx", "native", TDX_COLOR),
                ("tdx", "wasm", TDX_COLOR),
            ]
        ],
        "fig7",
    )

    if data is None:
        return

    labels, means, stds, colors = data

    plain_bar(
        labels,
        means,
        stds,
        colors,
        out / "eval7_e2e_with_collateral.pdf",
        fig_size=COMPARISON_BAR_FIG_SIZE,
        xtick_rotation=35,
        xtick_ha="right",
        xtick_fontsize=COMPARISON_XTICK_FONTSIZE,
        subplot_adjust=COMPARISON_BAR_ADJUST,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument(
        "--more-detail",
        action="store_true",
        help=(
            "also emit the extra detailed figures: "
            "eval1 without SGX, eval3 cold/warm/hot, and eval4 pie"
        ),
    )
    args = ap.parse_args()

    results = Path(args.results_dir)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if args.more_detail:
        fig1_hot_plus_verifiers(results, out)
    fig1_hot_plus_verifiers_with_sgx(results, out)
    fig3_merged(results, out, more_detail=args.more_detail)
    if args.more_detail:
        fig4_pie_only(results, out)
    fig7(results, out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
