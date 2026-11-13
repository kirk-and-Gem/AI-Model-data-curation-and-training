import json
import os
from mitreattack.stix20 import MitreAttackData

def process_matrix(matrix_file, matrix_name):
    if not os.path.exists(matrix_file):
        print(f"[!] Warning: {matrix_file} not found. Skipping {matrix_name}.")
        return []

    print(f"[*] Parsing {matrix_name} framework using MITRE SDK...")
    mitre_data = MitreAttackData(matrix_file)
    extracted_entries = []

    # 1. Grab Threat Groups
    groups = mitre_data.get_groups()
    print(f"    -> Found {len(groups)} Threat Groups")
    for group in groups:
        group_id = mitre_data.get_attack_id(group.id)
        group_desc = getattr(group, 'description', 'No formal description provided.')
        
        extracted_entries.append({
            "type": "group",
            "framework": matrix_name,
            "id": group_id,
            "name": group.name,
            "description": group_desc
        })

    # 2. Grab Software / Malware Tools
    software = mitre_data.get_software()
    print(f"    -> Found {len(software)} Software/Tools")
    for soft in software:
        soft_id = mitre_data.get_attack_id(soft.id)
        soft_desc = getattr(soft, 'description', 'No formal description provided.')
        
        extracted_entries.append({
            "type": "software",
            "framework": matrix_name,
            "id": soft_id,
            "name": soft.name,
            "description": soft_desc
        })

    return extracted_entries

if __name__ == "__main__":
    all_records = []
    
    # Process both of your downloaded files
    all_records.extend(process_matrix("enterprise-attack.json", "Enterprise"))
    all_records.extend(process_matrix("ics-attack.json", "ICS"))
    
    # Save the raw structural data to an intermediate file
    output_file = "mitre_raw_extracted.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=2)
        
    print(f"\n[+] Success! Extracted {len(all_records)} raw records to '{output_file}'.")

