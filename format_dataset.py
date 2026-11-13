import json

def generate_training_data():
    raw_file = "mitre_raw_extracted.json"
    output_file = "mitre_training_dataset.jsonl"
    
    try:
        with open(raw_file, "r", encoding="utf-8") as f:
            records = json.load(f)
    except FileNotFoundError:
        print(f"[!] Error: Could not find '{raw_file}'. please run build_dataset.py first.")
        return

    print(f"[*] Formatting {len(records)} entries into prompt/completion pairs...")
    
    with open(output_file, "w", encoding="utf-8") as out:
        for item in records:
            itype = item["type"]
            iname = item["name"]
            iid = item["id"]
            idesc = item["description"]
            iframework = item["framework"]
            
            # Diverse Prompt Templates for Groups
            if itype == "group":
                prompt = f"Please provide a concise summary of all known TTPs and tooling employed by {iname} ({iid}).\nThreat actor: {iname} ({iid})"
                completion = f"{iname} ({iid}) is an active threat group documented within the MITRE ATT&CK {iframework} matrix.\n\n**Description**\n{idesc}"
            
            # Diverse Prompt Templates for Software/Malware
            else:
                prompt = f"Profile the capabilities and operational context of the malware tool {iname}.\nTool: {iname} ({iid})"
                completion = f"Tool: {iname} ({iid})\nFramework Matrix: {iframework}\n\n**Capabilities and Context**\n{idesc}"
            
            # Construct the final JSON row
            jsonl_line = {
                "prompt": prompt,
                "completion": completion
            }
            
            out.write(json.dumps(jsonl_line, ensure_ascii=False) + "\n")
            
    print(f"[+] Dataset successfully compiled! Written to '{output_file}'")

if __name__ == "__main__":
    generate_training_data()

