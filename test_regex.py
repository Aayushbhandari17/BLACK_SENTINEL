from black_sentinel.detection.regex_engine import scan

with open("/Users/aayushbhandari/Desktop/test_secrets.env", "r") as f:
    content = f.read()

results = scan(
    content,
    "/Users/aayushbhandari/Desktop/test_secrets.env"
)

for r in results:
    print(r)
