import urllib.request, json
req = urllib.request.Request('http://127.0.0.1:8000/api/phishing/analyze', data=b'{"url":"https://en.wikipedia.org/wiki/India"}', headers={'Content-Type': 'application/json'})
res = urllib.request.urlopen(req)
print(json.dumps(json.loads(res.read().decode()), indent=2))
