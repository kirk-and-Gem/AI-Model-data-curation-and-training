import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, TextStreamer

MODEL_PATH = "/workspace/models/nova_cybersec_24b_standalone"

print("[*] Loading standalone model...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_PATH,
    torch_dtype=torch.bfloat16,
    device_map="auto"
)
model.eval()

streamer = TextStreamer(tokenizer, skip_prompt=True, skip_special_tokens=True)
SYSTEM_PROMPT = "You are a specialized cybersecurity assistant trained on MITRE ATT&CK, CISA advisories, and VulnCheck intelligence."

print("\n[✅] Ready! Type 'exit' to quit.\n" + "-" * 50)

while True:
    user_input = input("\nYou: ").strip()
    if user_input.lower() in ["exit", "quit"]:
        break
    if not user_input:
        continue

    prompt = (
        f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n"
        f"<|im_start|>user\n{user_input}<|im_end|>\n"
        f"<|im_start|>assistant\n"
    )

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    im_end_id = tokenizer.convert_tokens_to_ids("<|im_end|>")

    print("\nAssistant: ", end="")
    with torch.no_grad():
        model.generate(
            **inputs,
            max_new_tokens=1024,
            temperature=0.6,
            top_p=0.9,
            do_sample=True,
            eos_token_id=[tokenizer.eos_token_id, im_end_id],
            pad_token_id=tokenizer.pad_token_id,
            streamer=streamer
        )
