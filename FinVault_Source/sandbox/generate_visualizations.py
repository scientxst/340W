"""
FinVault PSSH Visualization Suite
=================================
Generates all four figures used in the DS 340W research paper:
  - Figure 1: Attack Success Rate (ASR) by model and attack type
  - Figure 2: Defense mechanism effectiveness (Detection Rate vs FPR)
  - Figure 3: Multi-step attack chain visibility (LogicGuard vs PSSH)
  - Figure 4: PSSH threat severity distribution

These charts reproduce the exact data reported in Tables I-III of the paper.
Each figure is saved as a high-resolution PNG in the figures/ subdirectory.

Author: Arjun Shokeen
Course: DS 340W - Spring 2026

Usage:
    python generate_visualizations.py
"""

import os
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless environments
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np


# ---------------------------------------------------------------------------
# Paper Data (Tables I-III)
# ---------------------------------------------------------------------------

# Table I: Attack Success Rate by model across 8 attack types
MODELS = ["Claude-Haiku-4.5", "GPT-4", "Qwen3-32B", "Qwen3-Max"]
ATTACK_TYPES = [
    "Prompt\nInjection",
    "Jailbreak",
    "Authority\nImperson.",
    "Social\nEngineer.",
    "Data\nExfiltration",
    "Transaction\nManip.",
    "Compliance\nEvasion",
    "Tool\nMisuse",
]

# ASR values per model (rows) x attack type (columns), in percent
ASR_DATA = np.array([
    [2.1, 3.5, 10.2, 12.8, 5.4, 7.1, 8.3, 4.2],   # Claude-Haiku-4.5
    [18.5, 22.3, 38.7, 42.1, 25.6, 30.2, 35.4, 14.8], # GPT-4
    [30.2, 35.1, 52.4, 58.3, 38.7, 45.6, 50.1, 26.8], # Qwen3-32B
    [38.5, 42.7, 60.1, 65.2, 45.3, 52.8, 56.4, 39.0], # Qwen3-Max
])

# Table II: Defense effectiveness
DEFENSES = ["Security\nPrompting", "LLaMA\nGuard 4", "LLaMA\nGuard 3", "GPT-OSS\nSafeguard"]
DETECTION_RATES = [89.2, 61.4, 37.1, 22.3]
FALSE_POSITIVE_RATES = [3.1, 30.2, 44.1, 12.5]

# Table III: LogicGuard vs PSSH comparative metrics
COMPARISON_METRICS = [
    "Hard\nBlocking",
    "Intelligence\nExtraction",
    "Chain\nVisibility",
    "Threat\nReporting",
]
LOGICGUARD_SCORES = [100, 0, 16.7, 0]     # 1/6 steps = 16.7% visibility
PSSH_SCORES = [0, 100, 100, 100]

# Phase 4 severity distribution from evaluation_run.log
SEVERITY_LABELS = ["Low", "Medium", "High", "Critical"]
SEVERITY_COUNTS = [0, 1, 5, 5]


# ---------------------------------------------------------------------------
# Plotting Helpers
# ---------------------------------------------------------------------------

# Consistent color palette across all figures
PALETTE = {
    "claude": "#6C5CE7",
    "gpt4": "#00B894",
    "qwen32b": "#FDCB6E",
    "qwenmax": "#E17055",
    "logicguard": "#636E72",
    "pssh": "#0984E3",
    "detection": "#0984E3",
    "fpr": "#D63031",
    "severity": ["#00B894", "#FDCB6E", "#E17055", "#D63031"],
}

MODEL_COLORS = [PALETTE["claude"], PALETTE["gpt4"], PALETTE["qwen32b"], PALETTE["qwenmax"]]


def setup_style():
    """Apply a clean, publication-ready matplotlib style."""
    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.labelsize": 11,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "figure.dpi": 150,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "axes.grid": True,
        "grid.alpha": 0.3,
        "axes.spines.top": False,
        "axes.spines.right": False,
    })


# ---------------------------------------------------------------------------
# Figure Generators
# ---------------------------------------------------------------------------

def fig1_attack_success_rates(output_dir: str) -> str:
    """
    Figure 1: Grouped bar chart of ASR by attack type across all four models.
    Reproduces Table I data visually. Each cluster of bars represents one attack
    type, with one bar per model colored distinctly.
    """
    fig, ax = plt.subplots(figsize=(10, 5))

    n_types = len(ATTACK_TYPES)
    n_models = len(MODELS)
    bar_width = 0.18
    x = np.arange(n_types)

    for i, (model, color) in enumerate(zip(MODELS, MODEL_COLORS)):
        offset = (i - n_models / 2 + 0.5) * bar_width
        bars = ax.bar(x + offset, ASR_DATA[i], bar_width, label=model, color=color, edgecolor="white", linewidth=0.5)

    ax.set_xlabel("Attack Type")
    ax.set_ylabel("Attack Success Rate (%)")
    ax.set_title("Figure 1: Attack Success Rate by Model and Attack Type")
    ax.set_xticks(x)
    ax.set_xticklabels(ATTACK_TYPES, ha="center")
    ax.set_ylim(0, 75)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter())
    ax.legend(loc="upper left", framealpha=0.9)

    path = os.path.join(output_dir, "fig1_asr_by_model.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  [SAVED] {path}")
    return path


def fig2_defense_effectiveness(output_dir: str) -> str:
    """
    Figure 2: Horizontal bar chart comparing Detection Rate and False Positive
    Rate for each defense mechanism. Reproduces Table II data. Detection Rate
    bars extend right (blue), FPR bars extend left (red) for visual contrast.
    """
    fig, ax = plt.subplots(figsize=(8, 4.5))

    y = np.arange(len(DEFENSES))
    height = 0.35

    ax.barh(y + height / 2, DETECTION_RATES, height, label="Detection Rate", color=PALETTE["detection"], edgecolor="white")
    ax.barh(y - height / 2, FALSE_POSITIVE_RATES, height, label="False Positive Rate", color=PALETTE["fpr"], edgecolor="white")

    ax.set_xlabel("Rate (%)")
    ax.set_title("Figure 2: Defense Mechanism Effectiveness")
    ax.set_yticks(y)
    ax.set_yticklabels(DEFENSES)
    ax.set_xlim(0, 100)
    ax.xaxis.set_major_formatter(mticker.PercentFormatter())
    ax.legend(loc="lower right", framealpha=0.9)

    # Annotate values on each bar
    for i, (dr, fpr) in enumerate(zip(DETECTION_RATES, FALSE_POSITIVE_RATES)):
        ax.text(dr + 1, i + height / 2, f"{dr:.1f}%", va="center", fontsize=8)
        ax.text(fpr + 1, i - height / 2, f"{fpr:.1f}%", va="center", fontsize=8)

    path = os.path.join(output_dir, "fig2_defense_effectiveness.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  [SAVED] {path}")
    return path


def fig3_chain_visibility(output_dir: str) -> str:
    """
    Figure 3: Side-by-side comparison of LogicGuard vs PSSH across four key
    metrics from the multi-step attack chain evaluation (Table III).
    Highlights that LogicGuard only achieves blocking while PSSH achieves
    intelligence extraction, full chain visibility, and threat reporting.
    """
    fig, ax = plt.subplots(figsize=(8, 5))

    x = np.arange(len(COMPARISON_METRICS))
    width = 0.3

    ax.bar(x - width / 2, LOGICGUARD_SCORES, width, label="LogicGuard (Baseline)", color=PALETTE["logicguard"], edgecolor="white")
    ax.bar(x + width / 2, PSSH_SCORES, width, label="PSSH (Novel)", color=PALETTE["pssh"], edgecolor="white")

    ax.set_ylabel("Score (%)")
    ax.set_title("Figure 3: LogicGuard vs. PSSH — Multi-Step Chain Evaluation")
    ax.set_xticks(x)
    ax.set_xticklabels(COMPARISON_METRICS, ha="center")
    ax.set_ylim(0, 115)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter())
    ax.legend(loc="upper center", framealpha=0.9)

    # Value labels
    for i, (lg, ps) in enumerate(zip(LOGICGUARD_SCORES, PSSH_SCORES)):
        ax.text(i - width / 2, lg + 2, f"{lg}%", ha="center", fontsize=9, fontweight="bold")
        ax.text(i + width / 2, ps + 2, f"{ps}%", ha="center", fontsize=9, fontweight="bold")

    path = os.path.join(output_dir, "fig3_chain_visibility.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  [SAVED] {path}")
    return path


def fig4_severity_distribution(output_dir: str) -> str:
    """
    Figure 4: Bar chart of the threat severity distribution extracted by PSSH
    during the evaluation (Phase 4 of evaluate_novelty.py output).
    Shows 0 low, 1 medium, 5 high, 5 critical — matching the evaluation log.
    """
    fig, ax = plt.subplots(figsize=(6, 4.5))

    bars = ax.bar(SEVERITY_LABELS, SEVERITY_COUNTS, color=PALETTE["severity"], edgecolor="white", linewidth=0.8, width=0.55)

    ax.set_xlabel("Threat Severity Level")
    ax.set_ylabel("Number of Interceptions")
    ax.set_title("Figure 4: PSSH Threat Severity Distribution")
    ax.set_ylim(0, max(SEVERITY_COUNTS) + 1.5)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))

    for bar, count in zip(bars, SEVERITY_COUNTS):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2, str(count), ha="center", fontsize=11, fontweight="bold")

    path = os.path.join(output_dir, "fig4_severity_distribution.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  [SAVED] {path}")
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """Generate all four research paper figures."""
    setup_style()

    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "figures")
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print("  FinVault PSSH — Research Paper Figure Generation")
    print("=" * 60)
    print()

    paths = [
        fig1_attack_success_rates(output_dir),
        fig2_defense_effectiveness(output_dir),
        fig3_chain_visibility(output_dir),
        fig4_severity_distribution(output_dir),
    ]

    print()
    print(f"  All {len(paths)} figures saved to: {output_dir}/")
    print("  These correspond to Figures 1-4 in the IEEE paper.")
    print("=" * 60)


if __name__ == "__main__":
    main()
