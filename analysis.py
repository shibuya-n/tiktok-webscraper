"""
EDA + matplotlib visualizations for tiktok-webscraper data.
Follows the 10-phase EDA plan: describes the dataset itself,
does not treat Scam Score / Risk Label as ground truth.
"""
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import re
from collections import Counter

plt.rcParams["figure.dpi"] = 110
plt.rcParams["font.size"] = 10
plt.rcParams["axes.spines.top"] = False
plt.rcParams["axes.spines.right"] = False

IN_PATH = r"C:\Users\Andy Duong\tiktok-webscraper\TikTok Scraper Data - Sheet1(1).csv"
OUT_DIR = r"C:\Users\Andy Duong\tiktok-webscraper\outputs"

# ── Load & clean ─────────────────────────────────────────────────────────
df = pd.read_csv(IN_PATH)
df = df.drop(columns=[c for c in df.columns if c.startswith("Unnamed")])

# One known row-shift (row 0: missing Hashtags caused columns to shift left) — drop it
bad = df["Is Ad"].astype(str).str.strip().str.lower().isin(["true", "false", "nan"]) == False
df = df.loc[~bad].reset_index(drop=True)

def parse_count(value) -> float:
    if pd.isna(value):
        return np.nan
    v = str(value).strip().upper().replace(",", "")
    if not v:
        return np.nan
    try:
        if v.endswith("M"):
            return float(v[:-1]) * 1_000_000
        if v.endswith("K"):
            return float(v[:-1]) * 1_000
        return float(v)
    except ValueError:
        return np.nan

for col in ["Likes", "Comments", "Shares", "Total Followers", "Total Likes"]:
    df[col + " (num)"] = df[col].apply(parse_count)

df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
df["Hashtag List"] = df["Hashtags"].fillna("").apply(
    lambda s: [h.strip() for h in s.split(",") if h.strip()]
)
df["Num Hashtags"] = df["Hashtag List"].apply(len)
df["Caption Length (words)"] = df["Description"].fillna("").apply(lambda s: len(s.split()))
df["Is Ad"] = df["Is Ad"].astype(str).str.strip().str.title()  # True/False/Nan

RISK_ORDER = ["Clean", "Low Risk", "Suspicious", "Probable Scam", "Almost Certainly a Scam"]
RISK_COLORS = {
    "Clean": "#4C9F70",
    "Low Risk": "#8FBF60",
    "Suspicious": "#E8B84B",
    "Probable Scam": "#E08636",
    "Almost Certainly a Scam": "#C0392B",
}

print(f"Loaded {len(df)} videos from {df['Author'].nunique()} unique creators.")

# ── Figure 1: Missing values ────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(9, 5))
miss = df.isna().sum().sort_values(ascending=True)
miss = miss[miss > 0]
ax.barh(miss.index, miss.values, color="#5B7DB1")
ax.set_xlabel("Missing count")
ax.set_title(f"Missing Values by Column (n={len(df)})")
for i, v in enumerate(miss.values):
    ax.text(v + 5, i, f"{v} ({v/len(df):.0%})", va="center", fontsize=8)
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/01_missing_values.png")
plt.close(fig)

# ── Figure 2: Histograms of core numeric features ──────────────────────
fig, axes = plt.subplots(2, 2, figsize=(11, 8))
specs = [
    ("Total Followers (num)", "Followers per Creator (log scale)", "#5B7DB1"),
    ("Likes (num)", "Video Likes (log scale)", "#C0392B"),
    ("Comments (num)", "Video Comments (log scale)", "#E8B84B"),
    ("Shares (num)", "Video Shares (log scale)", "#4C9F70"),
]
for ax, (col, title, color) in zip(axes.flat, specs):
    data = df[col].dropna()
    data = data[data > 0]
    ax.hist(np.log10(data), bins=30, color=color, edgecolor="white")
    ax.set_title(title)
    ax.set_xlabel("log10(count)")
    ax.set_ylabel("Videos")
fig.suptitle("Distribution of Core Engagement Metrics", fontsize=13, y=1.02)
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/02_engagement_histograms.png", bbox_inches="tight")
plt.close(fig)

# ── Figure 3: Videos per creator ────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
vpc = df.groupby("Author").size().sort_values(ascending=False)
axes[0].hist(vpc.values, bins=range(1, vpc.max() + 2), color="#5B7DB1", edgecolor="white")
axes[0].set_title("Videos per Creator (distribution)")
axes[0].set_xlabel("Videos from same creator")
axes[0].set_ylabel("Number of creators")

top20 = vpc.head(20)
axes[1].barh(top20.index[::-1], top20.values[::-1], color="#5B7DB1")
axes[1].set_title("Top 20 Most-Represented Creators")
axes[1].set_xlabel("Videos in dataset")
axes[1].tick_params(axis='y', labelsize=7)
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/03_videos_per_creator.png")
plt.close(fig)

# ── Figure 4: Boxplots (outliers) ───────────────────────────────────────
fig, ax = plt.subplots(figsize=(9, 5))
box_data = [np.log10(df[c].dropna().clip(lower=1)) for c in
            ["Likes (num)", "Comments (num)", "Shares (num)", "Total Followers (num)", "Total Likes (num)"]]
labels = ["Likes", "Comments", "Shares", "Followers", "Total Likes"]
bp = ax.boxplot(box_data, tick_labels=labels, patch_artist=True, showfliers=True, flierprops=dict(markersize=3, alpha=0.4))
for patch in bp['boxes']:
    patch.set_facecolor("#A9C4E8")
ax.set_ylabel("log10(count)")
ax.set_title("Engagement Metrics — Boxplots (log scale, outliers visible)")
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/04_boxplots_outliers.png")
plt.close(fig)

# ── Figure 5: Followers vs Likes scatter ────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 6))
plot_df = df.dropna(subset=["Total Followers (num)", "Likes (num)"])
plot_df = plot_df[(plot_df["Total Followers (num)"] > 0) & (plot_df["Likes (num)"] > 0)]
colors = plot_df["Risk Label"].map(RISK_COLORS).fillna("#999999")
ax.scatter(plot_df["Total Followers (num)"], plot_df["Likes (num)"], c=colors, alpha=0.5, s=18, edgecolor="none")
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("Creator Followers (log)")
ax.set_ylabel("Video Likes (log)")
ax.set_title("Followers vs. Video Likes\n(color = current Risk Label, for reference only)")
handles = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=c, markersize=7, label=lbl)
           for lbl, c in RISK_COLORS.items()]
ax.legend(handles=handles, fontsize=7, loc="upper left")
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/05_followers_vs_likes.png")
plt.close(fig)

# ── Figure 6: Hashtags vs Likes scatter ─────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 6))
plot_df2 = df.dropna(subset=["Likes (num)"])
plot_df2 = plot_df2[plot_df2["Likes (num)"] > 0]
ax.scatter(plot_df2["Num Hashtags"], plot_df2["Likes (num)"], alpha=0.4, s=18, color="#5B7DB1", edgecolor="none")
ax.set_yscale("log")
ax.set_xlabel("Number of Hashtags")
ax.set_ylabel("Video Likes (log)")
ax.set_title("Hashtag Count vs. Video Likes")
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/06_hashtags_vs_likes.png")
plt.close(fig)

# ── Figure 7: Correlation heatmap ───────────────────────────────────────
num_cols = ["Likes (num)", "Comments (num)", "Shares (num)", "Total Followers (num)",
            "Total Likes (num)", "Num Hashtags", "Caption Length (words)", "Scam Score"]
corr_df = df[num_cols].rename(columns=lambda c: c.replace(" (num)", ""))
corr = corr_df.corr()

fig, ax = plt.subplots(figsize=(7.5, 6.5))
im = ax.imshow(corr, cmap="RdBu_r", vmin=-1, vmax=1)
ax.set_xticks(range(len(corr.columns)))
ax.set_xticklabels(corr.columns, rotation=45, ha="right")
ax.set_yticks(range(len(corr.columns)))
ax.set_yticklabels(corr.columns)
for i in range(len(corr.columns)):
    for j in range(len(corr.columns)):
        ax.text(j, i, f"{corr.iloc[i, j]:.2f}", ha="center", va="center",
                 color="white" if abs(corr.iloc[i, j]) > 0.5 else "black", fontsize=8)
fig.colorbar(im, ax=ax, shrink=0.8, label="Pearson r")
ax.set_title("Correlation Matrix — Numeric Features")
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/07_correlation_heatmap.png")
plt.close(fig)

# ── Figure 8: Top 20 hashtags ───────────────────────────────────────────
all_tags = [t.lower() for tags in df["Hashtag List"] for t in tags]
tag_counts = Counter(all_tags).most_common(20)
fig, ax = plt.subplots(figsize=(9, 6))
tags, counts = zip(*tag_counts[::-1])
ax.barh(tags, counts, color="#5B7DB1")
ax.set_title("Top 20 Hashtags")
ax.set_xlabel("Occurrences")
ax.tick_params(axis='y', labelsize=8)
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/08_top_hashtags.png")
plt.close(fig)

# ── Figure 9: Top 20 words in captions (stopwords removed) ─────────────
STOPWORDS = set("""the a an and or but to of in on for with is are was were be been
i you he she it we they this that my your his her its our their at as by from
just so if not no do did does have has had will would can could should
your im ill youre its me my mine u ur""".split())
words = []
for desc in df["Description"].dropna():
    for w in re.findall(r"[a-zA-Z']+", desc.lower()):
        if len(w) > 2 and w not in STOPWORDS:
            words.append(w)
word_counts = Counter(words).most_common(20)
fig, ax = plt.subplots(figsize=(9, 6))
w, c = zip(*word_counts[::-1])
ax.barh(w, c, color="#4C9F70")
ax.set_title("Top 20 Caption Words (stopwords removed)")
ax.set_xlabel("Occurrences")
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/09_top_caption_words.png")
plt.close(fig)

# ── Figure 10: Caption length distribution ──────────────────────────────
fig, ax = plt.subplots(figsize=(8, 5))
ax.hist(df["Caption Length (words)"], bins=30, color="#8E6FB0", edgecolor="white")
ax.set_xlabel("Caption length (words)")
ax.set_ylabel("Videos")
ax.set_title("Caption Length Distribution")
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/10_caption_length.png")
plt.close(fig)

# ── Figure 11: Posting activity by hour / day-of-week ───────────────────
ts = df["Timestamp"].dropna()
fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
hour_counts = ts.dt.hour.value_counts().sort_index()
axes[0].bar(hour_counts.index, hour_counts.values, color="#5B7DB1")
axes[0].set_title("Scan Timestamps by Hour of Day")
axes[0].set_xlabel("Hour (24h)")
axes[0].set_ylabel("Videos scanned")

day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
day_counts = ts.dt.day_name().value_counts().reindex(day_order)
axes[1].bar(day_counts.index, day_counts.values, color="#E8B84B")
axes[1].set_title("Scan Timestamps by Day of Week")
axes[1].tick_params(axis='x', rotation=45)
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/11_temporal_activity.png")
plt.close(fig)

# ── Figure 12: Risk Label distribution (reference, not ground truth) ────
fig, ax = plt.subplots(figsize=(8, 5))
rl = df["Risk Label"].value_counts().reindex(RISK_ORDER).fillna(0)
ax.bar(rl.index, rl.values, color=[RISK_COLORS[r] for r in RISK_ORDER])
ax.set_title("Current Heuristic Risk Label Distribution\n(scorer output, not verified ground truth)")
ax.set_ylabel("Videos")
ax.tick_params(axis='x', rotation=20)
fig.tight_layout()
fig.savefig(f"{OUT_DIR}/12_risk_label_distribution.png")
plt.close(fig)

print("Saved 12 figures to", OUT_DIR)