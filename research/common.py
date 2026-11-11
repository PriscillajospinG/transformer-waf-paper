"""
Small helpers shared by the experiment scripts.

Nothing here changes results; it only removes duplicated code (loading
splits, fixing seeds, writing JSON, running a fine-tuned model).
"""
from __future__ import annotations

import json
import os
import random

import numpy as np
import pandas as pd

MAX_LEN = 256


def set_seed(seed: int) -> None:
    """Fix Python, NumPy and (if present) PyTorch seeds."""
    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except ImportError:
        pass


def load_table(path: str) -> pd.DataFrame:
    """Read a split from .parquet or .csv."""
    if path.endswith(".csv"):
        return pd.read_csv(path)
    return pd.read_parquet(path)


def save_json(obj, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2, default=_json_default)


def _json_default(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    raise TypeError(type(o))


def pick_text_column(df: pd.DataFrame, text_col: str | None) -> str:
    """Use the requested column, else 'text'."""
    col = text_col or "text"
    if col not in df.columns:
        raise ValueError(f"column '{col}' not in split; have {list(df.columns)}")
    return col


def model_logits(model_dir: str, texts: list[str], batch: int = 64,
                 device: str | None = None) -> np.ndarray:
    """Return raw logits (n, 2) of a fine-tuned Hugging Face classifier."""
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir)
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device).eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(texts), batch):
            enc = tok(texts[i:i + batch], truncation=True, max_length=MAX_LEN,
                      padding=True, return_tensors="pt").to(device)
            out.append(model(**enc).logits.float().cpu().numpy())
    return np.concatenate(out, axis=0) if out else np.zeros((0, 2))


def softmax_prob(logits: np.ndarray, temperature: float = 1.0) -> np.ndarray:
    """P(malicious) from logits, optionally temperature-scaled."""
    z = logits / float(temperature)
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e[:, 1] / e.sum(axis=1)


def model_probs(model_dir: str, texts: list[str], batch: int = 64,
                temperature: float = 1.0) -> np.ndarray:
    """P(malicious) for each text (temperature 1.0 = unchanged softmax)."""
    return softmax_prob(model_logits(model_dir, texts, batch), temperature)
