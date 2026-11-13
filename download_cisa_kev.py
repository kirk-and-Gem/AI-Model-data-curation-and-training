import urllib.request

url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
output_file = "cisa_kev.json"

urllib.request.urlretrieve(url, output_file)
print(f"Downloaded CISA KEV catalog to {output_file}")

