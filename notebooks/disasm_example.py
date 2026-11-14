"""Presentation for static byte decoding and source-linked evidence triage."""

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch, Rectangle
from matplotlib.ticker import MaxNLocator
from vgi_notebooks import finish, prose

SYNTHETIC = (
    "Source: authored 16-byte sequence · VGI disasm v0.4.0 · static linear sweep, never execution"
)
TRIAGE = "Source: committed hello-world Mach-O + authored documentation bytes · VGI disasm v0.4.0 · static evidence"


def validate_mode(value):
    if value not in {"x64", "x32"}:
        raise ValueError('MODE must be "x64" or "x32".')


def validate_minimum(value):
    if type(value) is not int or not 4 <= value <= 24:
        raise ValueError("MIN_CHARACTERS must be an integer from 4 through 24.")


def boundaries(spans, mode):
    modes = ["x64", "x32"]
    colors = {
        "Other instruction": "#267358",
        "Jump": "#456fba",
        "Return": "#7a5a99",
        "Fallback byte": "#c57b40",
    }
    payload_hex = spans.iloc[0].input_hex
    hex_bytes = [payload_hex[i : i + 2] for i in range(0, len(payload_hex), 2)]
    fig, ax = plt.subplots(figsize=(11.8, 5.6))
    for y, selected in enumerate(modes):
        for row in spans[spans["mode"] == selected].itertuples(index=False):
            ax.barh(
                y,
                row.size,
                left=row.byte_offset,
                height=0.54,
                color=colors[row.kind],
                edgecolor="white",
                linewidth=1.8,
            )
            ax.text(
                row.byte_offset + row.size / 2,
                y,
                row.mnemonic,
                ha="center",
                va="center",
                color="white",
                fontsize=10,
                weight="bold",
            )
    ax.add_patch(
        Rectangle(
            (0, modes.index(mode) - 0.31), 16, 0.62, fill=False, edgecolor="#1d3026", linewidth=2.4
        )
    )
    ax.set_yticks([0, 1], ["64-bit · x64", "32-bit · x32"])
    ax.set_xticks(
        np.arange(16) + 0.5, [f"{i}\n{value}" for i, value in enumerate(hex_bytes)], fontsize=9
    )
    ax.set_xlim(0, 16)
    ax.set_ylim(1.6, -0.6)
    ax.set_xlabel("Byte offset / hexadecimal value (same input in both rows)")
    ax.grid(False)
    fig.legend(
        handles=[Patch(facecolor=c, label=k) for k, c in colors.items()],
        loc="lower center",
        bbox_to_anchor=(0.55, 0.77),
        ncol=4,
        fontsize=10,
    )
    finish(
        fig,
        "The same bytes split into different instruction boundaries",
        f"Outlined row: {mode} · fixed x86 input · base address 0x1000",
        SYNTHETIC,
        name="01-instruction-boundaries",
    )


def decoding_profile(summary, mode):
    summary = summary.set_index("mode").loc[["x64", "x32"]].reset_index()
    fig, axes = plt.subplots(1, 2, figsize=(11.2, 5.4))
    for ax, col, label, maximum in [
        (
            axes[0],
            "decoded_instructions",
            "Decoded instructions (rows)",
            max(summary.decoded_instructions) * 1.25,
        ),
        (axes[1], "decoded_percent", "Input bytes decoded as instructions (%)", 112),
    ]:
        ax.barh(summary["mode"], summary[col], color=["#267358", "#456fba"], height=0.55)
        for y, value in enumerate(summary[col]):
            label_value = f"{value:.2f}%" if col == "decoded_percent" else str(int(value))
            ax.text(value + maximum * 0.02, y, label_value, va="center")
        ax.set_xlim(0, maximum)
        ax.invert_yaxis()
        ax.set_xlabel(label)
        ax.grid(axis="x")
    axes[0].xaxis.set_major_locator(MaxNLocator(integer=True))
    axes[1].set_xticks([0, 25, 50, 75, 100])
    finish(
        fig,
        "More decoded bytes do not establish the intended mode",
        f"Selected interpretation: {mode} · fallback bytes stay in the denominator",
        SYNTHETIC,
        name="02-decoding-profile",
    )


def section_profile(sections, inventory):
    fig, ax = plt.subplots(figsize=(10.8, 5.7))
    colors = {"code": "#267358", "rodata": "#456fba", "data": "#7a5a99", "other": "#c57b40"}
    labels = sections["name"].str.replace(",", "\n", regex=False)
    bars = ax.bar(labels, sections["size"], color=[colors[k] for k in sections.kind], width=0.65)
    ax.bar_label(bars, padding=4)
    ax.set_ylim(0, max(sections["size"]) * 1.20)
    ax.set_ylabel("Reported section size (bytes)")
    ax.tick_params(axis="x", labelsize=9)
    ax.grid(axis="y")
    fig.legend(
        handles=[Patch(color=v, label=k) for k, v in colors.items()],
        loc="lower center",
        bbox_to_anchor=(0.55, 0.77),
        ncol=4,
    )
    total = int(sections["size"].sum())
    file_bytes = int(inventory.iloc[0].file_bytes)
    finish(
        fig,
        "Section rows describe selected regions of the file",
        f"{len(sections)} sections total {total:,} bytes · whole Mach-O file {file_bytes:,} bytes · different scopes",
        TRIAGE,
        name="03-container-sections",
    )
    prose(
        f"The worker reports **{total:,} section bytes** inside a **{file_bytes:,}-byte file**. Headers, padding and other container data are outside these section rows; the difference is not evidence of hidden code. Executable sections describe a static container flag, not a record of execution."
    )


def string_sensitivity(sensitivity, minimum):
    fig, axes = plt.subplots(1, 2, figsize=(11.2, 5.6))
    for ax, sample, color in zip(
        axes, ["Mach-O", "Documentation control"], ["#267358", "#456fba"], strict=True
    ):
        data = sensitivity[sensitivity["sample"] == sample]
        ax.step(data.minimum_characters, data.string_rows, where="post", color=color, linewidth=2.3)
        selected = data[data.minimum_characters == minimum].iloc[0]
        ax.axvline(minimum, color="#c57b40", linestyle="--", linewidth=1.5)
        ax.scatter([minimum], [selected.string_rows], color=color, s=55, zorder=3)
        ax.annotate(
            f"{int(selected.string_rows)} rows",
            (minimum, selected.string_rows),
            xytext=(8, 12),
            textcoords="offset points",
            fontsize=10,
        )
        ax.set_title(sample, fontsize=12, pad=12)
        ax.set_xlim(3.5, 25)
        ax.set_ylim(0, max(data.string_rows) * 1.25)
        ax.set_xticks([4, 8, 12, 16, 20, 24])
        ax.yaxis.set_major_locator(MaxNLocator(integer=True))
        ax.set_xlabel("Minimum printable characters per string")
        ax.set_ylabel("Extracted string rows")
        ax.grid(axis="y")
    finish(
        fig,
        "A stricter string threshold removes visible evidence",
        f"Selected threshold: {minimum} characters · separate count scales · capability rules retain their fixed minimum of 4",
        TRIAGE,
        name="04-string-threshold",
    )
