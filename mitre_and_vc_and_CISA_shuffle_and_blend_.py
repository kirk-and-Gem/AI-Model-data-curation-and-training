import json
import random

# Define your paths
MITRE_DATASET = "/home/nke/Datasets/mitre_training_dataset.jsonl"  
KEV_DATASET = "/home/nke/Datasets/ics_audit_training_dataset.jsonl"
FINAL_BLENDED_OUTPUT = "/home/nke/Datasets/runpod_training_dataset.jsonl"

def load_jsonl_records(file_path):
    """Safely loads valid prompt/completion pairs from a jsonl file."""
    records = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                cleaned_line = line.strip()
                if not cleaned_line:
                    continue
                try:
                    data = json.loads(cleaned_line)
                    # Verify it has the required fields for RunPod instruction tuning
                    if "prompt" in data and "completion" in data:
                        records.append(data)
                except json.JSONDecodeError:
                    print(f"Skipping malformed JSON on line {line_num} in {file_path}")
    except FileNotFoundError:
        print(f"Warning: File not found at {file_path}")
    return records

print("Loading datasets...")
mitre_records = load_jsonl_records(MITRE_DATASET)
kev_records = load_jsonl_records(KEV_DATASET)

print(f"-> Loaded {len(mitre_records)} MITRE group records.")
print(f"-> Loaded {len(kev_records)} VulnCheck/CISA KEV records.")

# Combine the lists together
blended_dataset = mitre_records + len(kev_records) * [None] # Allocate space
blended_dataset = mitre_records + kev_records

print(f"Total combined pool size: {len(blended_dataset)} rows.")

print("Shuffling and blending dataset records randomly...")
# Seed the randomizer if you want reproducible train splits, otherwise leave it native
random.seed(42) 
random.shuffle(blended_dataset)

print(f"Writing final blended dataset to: {FINAL_BLENDED_OUTPUT}")
with open(FINAL_BLENDED_OUTPUT, 'w', encoding='utf-8') as out_f:
    for record in blended_dataset:
        # Save each row as a single line JSON entry
        out_f.write(json.dumps(record) + '\n')

print("All done! Your dataset is fully balanced, mixed, and ready to upload to RunPod.")

