"""
DISABLED — do not use in experiments or production.

This module is intentionally not runnable. Two unfixed problems make it unsafe
and unpublishable:

  1. It instantiated WAFTransformer(vocab_size=..., d_model=..., num_layers=...)
     with constructor arguments the class does not accept -> immediate crash.
  2. Its core assumption ("every request that was allowed is benign, label 0")
     is a label-poisoning vulnerability: an attacker whose payload slips through
     once gets it reinforced as benign. Self-training on unlabeled production
     traffic without human verification is a known attack surface.

For the paper, present safe online adaptation as FUTURE WORK (human-in-the-loop
labeling, verified feedback, drift monitoring). Do NOT present or benchmark the
logic below. Kept only for history.
"""
raise SystemExit(
    "online_learning.py is disabled by design (see module docstring). "
    "Safe online adaptation is future work, not part of the evaluated system."
)


import torch  # noqa: E402  (unreachable; retained for reference)
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
import os
import sys

# Add parent dir
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from waf.model.transformer import WAFTransformer
from waf.model.tokenizer import HttpTokenizer
from waf.utils.log_parser import NginxLogParser
from waf.data.normalizer import RequestNormalizer
from waf.train.train_pipeline import WAFDataset

def online_learning(log_file="../../nginx/logs/access.log", epochs=1):
    print("--- Starting Online Learning Cycle ---")
    
    # 1. Load Artifacts
    TOKENIZER_PATH = "waf/model/weights/tokenizer.json"
    MODEL_PATH = "waf/model/weights/waf_model.pth"
    
    if not os.path.exists(MODEL_PATH):
        print("Model not found. Run initial training first.")
        return

    device = torch.device("cpu")
    
    tokenizer = HttpTokenizer()
    tokenizer.load(TOKENIZER_PATH)
    
    model = WAFTransformer(vocab_size=1000, d_model=64, num_layers=2, num_classes=2)
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
    model.to(device)
    model.train() # Set to train mode
    
    # 2. Extract New Data from Logs
    # In a real system, we'd track file offset. Here we read the whole file for the demo.
    parser = NginxLogParser()
    normalizer = RequestNormalizer()
    
    new_data = []
    # For demo, we treat all viewed logs as "Benign" or "Self-Supervised" 
    # But usually we need feedback. 
    # Constraint: "If a request is unseen but allowed -> Log it -> Incrementally fine-tune"
    # This implies we assume allowed requests are benign? Or we just learn distribution?
    # Let's assume we maintain them as class 0 (Benign) to reinforce "normal" behavior.
    # If the user manually labels attacks, that's different.
    # We will assume new logs are BENIGN (0) for adapting to drift.
    
    if not os.path.exists(log_file):
        print(f"Log file {log_file} not found.")
        return

    print(f"Reading logs from {log_file}...")
    for entry in parser.parse_file(log_file):
        # Skip WAF checks
        if "/_waf_check" in entry['uri']:
            continue
        
        # Consider only successful requests as benign?
        if entry['status'] < 400:
            norm = normalizer.normalize(entry)
            new_data.append(norm)
            
    if not new_data:
        print("No valid new data found for training.")
        return
        
    print(f"Found {len(new_data)} samples for fine-tuning.")
    
    # 3. Fine-tune
    # Create dataset with label 0 (Benign)
    labels = [0] * len(new_data)
    dataset = WAFDataset(new_data, labels, tokenizer)
    dataloader = DataLoader(dataset, batch_size=8, shuffle=True)
    
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.0001) # Low LR for fine-tuning
    
    for epoch in range(epochs):
        total_loss = 0
        for inputs, targets in dataloader:
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            
        print(f"[Fine-tune] Epoch {epoch+1} Loss: {total_loss/len(dataloader):.4f}")
        
    # 4. Save Updated Model
    torch.save(model.state_dict(), MODEL_PATH)
    print("Updated model saved.")

if __name__ == "__main__":
    online_learning()
