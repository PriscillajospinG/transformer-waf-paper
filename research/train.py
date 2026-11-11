"""
Fine-tune a transformer to classify HTTP requests as benign (0) / malicious (1).

Supports three base models for the "domain-pretrained vs general" experiment:
  --model bert-base-uncased           (general LM baseline)
  --model ehsanaghaei/SecureBERT      (real domain-pretrained cyber LM)
  --model distilbert-base-uncased     (latency-optimized variant)

Run once per base model per training dataset. Needs a GPU for reasonable time
(Colab T4 is enough). Outputs a saved model dir consumed by evaluate.py.

Loss: standard (unweighted) two-class cross-entropy, as computed by the
Hugging Face Trainer. Optimiser: AdamW, linear warmup (10%) then linear
decay, weight decay 0.01, early stopping on validation F1 (patience 2).

Usage
-----
  python train.py --train data/splits/csic2010/train.parquet \
                  --val   data/splits/csic2010/val.parquet \
                  --model bert-base-uncased \
                  --out models/bert_csic_s42 --epochs 3 --seed 42

  # several seeds (for mean +/- std in the paper):
  for s in 42 1 7 13 21; do python train.py ... --seed $s --out models/bert_csic_s$s; done
"""
from __future__ import annotations

import argparse
import json
import os
import time

import numpy as np
import pandas as pd
from datasets import Dataset
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          Trainer, TrainingArguments, EarlyStoppingCallback)

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


def to_hf(df: pd.DataFrame, tokenizer, text_col: str = "text"):
    df = df[[text_col, "label"]].rename(columns={text_col: "text"})
    ds = Dataset.from_pandas(df, preserve_index=False)
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
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--text-col", default="text",
                    help="text (default), text_decoded or text_raw")
    args = ap.parse_args()

    from transformers import set_seed
    set_seed(args.seed)

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model, num_labels=2)

    train_ds = to_hf(pd.read_parquet(args.train), tokenizer, args.text_col)
    val_ds = to_hf(pd.read_parquet(args.val), tokenizer, args.text_col)

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
        seed=args.seed,
        data_seed=args.seed,
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

    t0 = time.time()
    trainer.train()
    train_seconds = time.time() - t0
    val_metrics = trainer.evaluate()
    print("Validation:", val_metrics)
    trainer.save_model(args.out)
    tokenizer.save_pretrained(args.out)
    # Record exactly how this model was produced (goes with the results).
    import torch, transformers
    meta = {
        "base_model": args.model, "seed": args.seed, "text_col": args.text_col,
        "epochs": args.epochs, "batch": args.batch, "lr": args.lr,
        "weight_decay": 0.01, "warmup_ratio": 0.1, "max_len": MAX_LEN,
        "loss": "unweighted cross-entropy", "train_file": args.train,
        "val_file": args.val, "train_seconds": round(train_seconds, 1),
        "best_val": val_metrics,
        "torch": torch.__version__, "transformers": transformers.__version__,
        "device": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "cpu",
    }
    with open(os.path.join(args.out, "run_meta.json"), "w") as fh:
        json.dump(meta, fh, indent=2)
    print(f"Saved fine-tuned model to {args.out}")


if __name__ == "__main__":
    main()
