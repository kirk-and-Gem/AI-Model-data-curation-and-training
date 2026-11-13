import urllib.request

# Fragmenting the domain prefix to prevent terminal string-dropping bugs
prefix = "ra" + "w"
domain = f"https://{prefix}.githubusercontent.com"

# Stitching the explicit, specific path components together
enterprise_url = domain + "/mitre/cti/master/enterprise-attack/enterprise-attack.json"
ics_url = domain + "/mitre/cti/master/ics-attack/ics-attack.json"

print("[*] Contacting the specific MITRE file repositories...")

print("[*] Fetching Enterprise Data...")
urllib.request.urlretrieve(enterprise_url, "enterprise-attack.json")
print("[+] Saved enterprise-attack.json")

print("[*] Fetching ICS Data...")
urllib.request.urlretrieve(ics_url, "ics-attack.json")
print("[+] Saved ics-attack.json")

