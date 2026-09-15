import urllib.request
import zipfile
import json
import io

print("Downloading Tranco list...")
req = urllib.request.Request('https://tranco-list.eu/top-1m.csv.zip', headers={'User-Agent': 'Mozilla/5.0'})
res = urllib.request.urlopen(req)
zip_data = res.read()

print(f"Downloaded {len(zip_data)} bytes. Extracting...")
with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
    filename = z.namelist()[0]
    print(f"Reading {filename}...")
    with z.open(filename) as f:
        domains = []
        for i, line in enumerate(f):
            if i >= 50000:
                break
            # Format: rank,domain
            parts = line.decode('utf-8').strip().split(',')
            if len(parts) == 2:
                domains.append(parts[1])

print(f"Extracted {len(domains)} domains. Saving to JSON...")
with open('backend/data/trusted_domains.json', 'w') as out:
    json.dump(domains, out)
print("Done.")
