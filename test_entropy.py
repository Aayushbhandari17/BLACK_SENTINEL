from black_sentinel.detection.entropy_engine import scan

with open("/Users/aayushbhandari/Desktop/test_entropy.txt", "r") as f:
    content = f.read()

results = scan(content)

for r in results:
    print(r)
