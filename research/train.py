"""
Fine-tune a transformer to classify HTTP requests as benign (0) / malicious (1).

Supports three base models for the "domain-pretrained vs general" experiment:
  --model bert-base-uncased           (general LM baseline)
  --model ehsanaghaei/SecureBERT      (real domain-pretrained cyber LM)
  --model distilbert-base-uncased     (latency-optimized variant)

Run once per base model per training dataset. Needs a GPU for reasonable time
(Colab T4 is enough). Outputs a saved model dir consumed by evaluate.py.

Usage
-----
  python train.py --train data/splits/csic2010/train.parquet \
                  --val   data/splits/csic2010/val.parquet \
                  --model bert-base-uncased \
                  --out models/bert_csic --epochs 3
"""
from __future__ import annotations

import argparse
import numpy as np
import pandas as pd
from datasets import Dataset
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          Trainer, TrainingArguments, EarlyStoppingCallback)

SEED = 42
MAX_LEN = 256


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=1)
    return {
        "accuracy": accuracy_score(labels, preds),
        "precision": precision_score(labels, preds, zero_division=0),
        "recall": recall_score(labels, preds, zero_division=0),
        "f1": f1_score(labels, preds, zero_division=0),
    }


def to_hf(df: pd.DataFrame, tokenizer):
    ds = Dataset.from_pandas(df[["text", "label"]], preserve_index=False)
    return ds.map(
        lambda b: tokenizer(b["text"], truncation=True, max_length=MAX_LEN,
                            padding="max_length"),
        batched=True,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--val", required=True)
    ap.add_argument("--model", default="bert-base-uncased")
    ap.add_argument("--out", required=True)
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-5)
    args = ap.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model, num_labels=2)

    train_ds = to_hf(pd.read_parquet(args.train), tokenizer)
    val_ds = to_hf(pd.read_parquet(args.val), tokenizer)

    targs = TrainingArguments(
        output_dir=args.out + "_ckpt",
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=args.batch * 2,
        learning_rate=args.lr,
        weight_decay=0.01,
        warmup_ratio=0.1,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_steps=50,
        seed=SEED,
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=targs,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
    )

    trainer.train()
    print("Validation:", trainer.evaluate())
    trainer.save_model(args.out)
    tokenizer.save_pretrained(args.out)
    print(f"Saved fine-tuned model to {args.out}")


if __name__ == "__main__":
    main()
