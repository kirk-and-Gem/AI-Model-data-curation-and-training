import io
import requests
import zipfile

API_TOKEN = "vulncheck_***"
output_dir = "/home/nke/Datasets/"

headers = {"Accept": "application/json", "Authorization": f"Bearer {API_TOKEN}"}

# 1. Get the JSON metadata response
response = requests.get(
    "https://api.vulncheck.com/v3/backup/vulncheck-kev", headers=headers
)
response.raise_for_status()

# 2. Extract the real pre-signed S3 download URL from the JSON data list
download_url = response.json()["data"][0]["url"]

print("Fetching the real ZIP archive from S3...")
# 3. Stream and extract the actual ZIP payload
zip_response = requests.get(download_url)
zip_response.raise_for_status()

with zipfile.ZipFile(io.BytesIO(zip_response.content)) as z:
  z.extractall(output_dir)
  print(f"Success! Files extracted directly to {output_dir}")

