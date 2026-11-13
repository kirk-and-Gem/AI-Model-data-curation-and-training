import json

# Define your input and output paths
VULNCHECK_INPUT = "/home/nke/Datasets/vckev_llm_training.jsonl"
CISA_INPUT = "/home/nke/Datasets/known_exploited_vulnerabilities.json"
OUTPUT_GOAL_FILE = "/home/nke/Datasets/ics_audit_training_dataset.jsonl"

# The filter list to isolate physical & OT site auditing vendors
OT_VENDORS = [
    "Siemens", "Rockwell Automation", "Schneider Electric", "Honeywell", 
    "Advantech", "Moxa", "ABB", "GE", "Mitsubishi Electric", "Omron",
    "Yokogawa", "Phoenix Contact", "SonicWall", "Cisco", "Fortinet"
]

def is_ot_related(vendor_string):
    """Returns True if the vendor matches our OT/ICS auditing target list."""
    if not vendor_string:
        return False
    return any(ot.lower() in vendor_string.lower() for ot in OT_VENDORS)

def convert_vulncheck_to_goal(line_str):
    """Converts a standard VulnCheck chat-formatted line into prompt/completion."""
    try:
        row = json.loads(line_str)
        messages = row.get("messages", [])
        
        user_content = ""
        assistant_content = ""
        
        for msg in messages:
            if msg["role"] == "user":
                user_content = msg["content"]
            elif msg["role"] == "assistant":
                assistant_content = msg["content"]
                
        # Clean up unsightly list brackets inside the raw text string if they exist
        # e.g., changing affecting ['CVE-2014-6332'] to CVE-2014-6332
        user_content = user_content.replace("['", "").replace("']", "")
        assistant_content = assistant_content.replace("['", "").replace("']", "")
        
        # Check if this row belongs to an OT vendor based on the text
        if any(ot.lower() in user_content.lower() for ot in OT_VENDORS):
            return {
                "prompt": user_content,
                "completion": assistant_content
            }
    except Exception:
        pass
    return None

def convert_cisa_to_goal(item):
    """Converts a raw CISA KEV JSON object directly into prompt/completion."""
    vendor = item.get("vendorProject", "Unknown Vendor")
    
    # Early exit if it's an unneeded IT software/vendor
    if not is_ot_related(vendor):
        return None
        
    cve = item.get("cveID", "Unknown CVE")
    product = item.get("product", "Unknown Product")
    description = item.get("shortDescription", "No description available.")
    remediation = item.get("requiredAction", "Apply updates per vendor instructions.")
    vuln_name = item.get("vulnerabilityName", "Vulnerability")

    user_prompt = (
        f"During our facility site audit, we discovered a vulnerability flagged as {cve} "
        f"affecting our {vendor} {product} equipment. What does this vulnerability do, and what remediation action must we take?"
    )
    
    assistant_response = (
        f"Vulnerability Overview for {cve}:\n"
        f"This vulnerability affects {vendor} {product} ({vuln_name}). {description}\n\n"
        f"Required Audit Remediation Action:\n"
        f"{remediation}"
    )
    
    return {
        "prompt": user_prompt,
        "completion": assistant_response
    }

# Main Execution Pipeline
total_written = 0

with open(OUTPUT_GOAL_FILE, 'w') as out_f:
    
    # 1. Process VulnCheck data if you already generated it
    try:
        print("Parsing VulnCheck file records...")
        with open(VULNCHECK_INPUT, 'r') as vc_f:
            for line in vc_f:
                converted = convert_vulncheck_to_goal(line)
                if converted:
                    out_f.write(json.dumps(converted) + '\n')
                    total_written += 1
    except FileNotFoundError:
        print(f"Skipping VulnCheck: {VULNCHECK_INPUT} not found yet.")

    # 2. Process Raw CISA JSON data archive
    try:
        print("Parsing raw CISA JSON archive data...")
        with open(CISA_INPUT, 'r') as cisa_f:
            cisa_data = json.load(cisa_f)
            
            # Direct dictionary check vs straight array wrapper matching CISA layout
            entries = cisa_data.get("vulnerabilities", cisa_data)
            if isinstance(entries, dict):
                entries = entries.get("data", [])
                
            for item in entries:
                converted = convert_cisa_to_goal(item)
                if converted:
                    out_f.write(json.dumps(converted) + '\n')
                    total_written += 1
    except FileNotFoundError:
        print(f"Skipping CISA: {CISA_INPUT} not found.")

print(f"\nSuccess! Standardized dataset created with {total_written} OT entries.")
print(f"Saved directly to: {OUTPUT_GOAL_FILE}")

