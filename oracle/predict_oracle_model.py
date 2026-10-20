import pandas as pd
import joblib
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix

import os

BASE_DIR = "/data/mirayrdm/scam-paper-codes/oracle_model/"
MODEL_PATH = f"{BASE_DIR}oracle_pipeline.pkl"
FEATURE_POOL_DIR = os.environ.get(
    "ORACLE_FEATURE_BASE_DIR",
    "/data/mirayrdm/scam/scam_graph_data_2/collected_features_candidate_pool_excluded_2",
)
SCAM_URL = os.environ.get("ORACLE_SCAM_URL", "candidate_pool_excluded_2")
TEST_CSV = f"{FEATURE_POOL_DIR}/raw_features_{SCAM_URL}.csv"

bundle = joblib.load(MODEL_PATH)
pipeline = bundle["pipeline"]
feature_cols = bundle["feature_cols"]

df = pd.read_csv(TEST_CSV)

# Make sure any missing columns exist
missing = [c for c in feature_cols if c not in df.columns]
for c in missing:
    df[c] = 0

new_threshold = 0.85
X = df[feature_cols]
proba = pipeline.predict_proba(X)[:, 1]
pred = (proba >= new_threshold).astype(int)

out = pd.DataFrame({
    "domain": df["domain"] if "domain" in df.columns else range(len(df)),
    "fraud_probability": proba,
    "is_fraud": pred,
    "label": df["label"]
})

cm = confusion_matrix(df['label'], pred)

plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=['Predicted Benign', 'Predicted Scam'], 
            yticklabels=['Actual Benign', 'Actual Scam'])

plt.ylabel('Actual Label')
plt.xlabel('Predicted Label')
plt.title(f'Oracle Model Confusion Matrix (Threshold {new_threshold})')
plt.savefig('confusion_matrix.png')
print("Confusion matrix saved as confusion_matrix.png")

print(f"Results with Threshold {new_threshold}:")
print(classification_report(df["label"], pred))
out = out.sort_values(by="fraud_probability", ascending=False).reset_index(drop=True)

out.to_csv(f"{FEATURE_POOL_DIR}/predictions.csv", index=False)
print("Saved predictions.csv")