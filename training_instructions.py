import os
os.environ["TORCH_COMPILE_DISABLE"] = "1"
os.environ["BITSANDBYTES_NOWELCOME"] = "1"
import torch
import json
from datasets import Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    DataCollatorForSeq2Seq
)
from peft import LoraConfig, get_peft_model

# 1. Staging Absolute Directory Maps
MODEL_PATH = "/workspace/models/cybersec_24b_aliterated"  
DATASET_PATH = "/workspace/runpod_training_dataset.jsonl"
OUTPUT_DIR = "/workspace/models/nova_cybersec_24b_abliterated_w_mitre_cisa_and_vulncheck_training"

print("[*] Initializing Tokenizer Pipeline...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"

IM_START_ID = tokenizer.encode("<|im_start|>", add_special_tokens=False)
IM_END_ID = tokenizer.encode("<|im_end|>", add_special_tokens=False)
USER_ID = tokenizer.encode("user", add_special_tokens=False)
ASSISTANT_ID = tokenizer.encode("assistant", add_special_tokens=False)
SYSTEM_ID = tokenizer.encode("system", add_special_tokens=False)
NEWLINE_ID = tokenizer.encode("\n", add_special_tokens=False)

# 2. High-Performance Flattened Token-Masking Engine
def process_token_mask_sequence(examples):
    batch_input_ids = []
    batch_attention_mask = []
    batch_labels = []
    
    for messages_list in examples["messages"]:
        input_ids = []
        labels = []
        
        for msg in messages_list:
            role = msg["role"]
            content = msg["content"]
            
            if role == "system":
                role_id = SYSTEM_ID
            elif role == "user":
                role_id = USER_ID
            else:
                role_id = ASSISTANT_ID
                
            header_tokens = IM_START_ID + role_id + NEWLINE_ID
            content_tokens = tokenizer.encode(content, add_special_tokens=False)
            footer_tokens = IM_END_ID + NEWLINE_ID
            
            segment = header_tokens + content_tokens + footer_tokens
            input_ids.extend(segment)
            
            if role == "assistant":
                labels.extend(segment)
            else:
                labels.extend([-100] * len(segment))
                
        if len(input_ids) > 4096:
            input_ids = input_ids[:4096]
            labels = labels[:4096]
            
        batch_input_ids.append(input_ids)
        batch_attention_mask.append([1] * len(input_ids))
        batch_labels.append(labels)
        
    return {
        "input_ids": batch_input_ids,
        "attention_mask": batch_attention_mask,
        "labels": batch_labels
    }

print("[*] Processing Curation Records and Injecting Masks via Multi-Processing...")
with open(DATASET_PATH, 'r', encoding='utf-8') as f:
    raw_data = [json.loads(line) for line in f if line.strip()]

raw_dataset = Dataset.from_list(raw_data)

processed_dataset = raw_dataset.map(
    process_token_mask_sequence, 
    batched=True, 
    batch_size=1000,
    num_proc=4, 
    remove_columns=["messages"]
)

# 3. Native Model Instantiation across all Blackwell GPUs
print("[*] Instantiating Open-Weight Model in Native BF16 across cluster...")
model = AutoModelForCausalLM.from_pretrained(
    MODEL_PATH,
    torch_dtype=torch.bfloat16,
    device_map={"": int(os.environ.get("LOCAL_RANK", 0))}
)

# 4. LoRA Adapter Matrices Configuration
peft_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM"
)
model = get_peft_model(model, peft_config)

# 5. Core Native Accelerated Training Arguments
training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    per_device_train_batch_size=4,       
    gradient_accumulation_steps=2,       
    learning_rate=2e-4,
    logging_steps=1,
    num_train_epochs=3,
    bf16=True,                           
    fp16=False,
    warmup_steps=100,                   
    save_strategy="epoch",
    report_to="none",
    gradient_checkpointing=True,         
    tf32=True,                           
    dataloader_num_workers=4,            
    dataloader_pin_memory=True           
)

# Dynamic Sequence Padding Collator
data_collator = DataCollatorForSeq2Seq(
    tokenizer=tokenizer,
    model=model,
    padding=True
)

print("[🚀] Pipeline Initialization Finalized. Launching compute run...")
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=processed_dataset,
    data_collator=data_collator
)

trainer.train()

print(f"[🔥] Training sequence finalized. Saving adapter arrays to {OUTPUT_DIR}")
trainer.model.save_pretrained(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)
