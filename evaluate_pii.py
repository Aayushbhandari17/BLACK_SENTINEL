import json
import os
import sys
from pathlib import Path

# Add the project directory to sys.path so we can import black_sentinel
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from black_sentinel.discovery.engine import ScanEngine

def clean_val(v, t):
    if not v:
        return ""
    v = str(v).strip().lower()
    
    # Normalize phone numbers (strip +91, 0, non-digits)
    if t == "phone":
        digits = "".join(c for c in v if c.isdigit())
        if len(digits) == 10:
            return digits
        if len(digits) == 12 and digits.startswith("91"):
            return digits[2:]
        if len(digits) > 10 and digits.startswith("0"):
            return digits.lstrip("0")
        return digits
        
    # Normalize AADHAAR (strip spaces/hyphens)
    if t == "aadhaar":
        return "".join(c for c in v if c.isdigit())
        
    # General normalization (alphanumeric only, lowercase)
    return "".join(c for c in v if c.isalnum())

def map_scanner_type_to_gt(f):
    rule_name = f.get("rule_name") or ""
    entity_type = f.get("entity_type") or f.get("rule_id") or ""
    
    t = (entity_type or rule_name).lower()
    
    mapping = {
        "aadhaar": "aadhaar",
        "aadhaar_number": "aadhaar",
        "address": "address",
        "physical_address": "address",
        "bank_account": "bank_account",
        "credit_card": "credit_card",
        "driving_licence": "dl",
        "dl": "dl",
        "dob": "dob",
        "date_of_birth": "dob",
        "email": "email",
        "email_address": "email",
        "ifsc_code": "ifsc",
        "ifsc": "ifsc",
        "ip_address": "ip_address",
        "name": "name",
        "person_name": "name",
        "pan_card": "pan",
        "pan": "pan",
        "passport": "passport",
        "passport_india": "passport",
        "phone_number": "phone",
        "indian_phone": "phone",
        "phone": "phone",
        "ssn": "ssn",
        "social_security_number": "ssn",
        "upi_id": "upi",
        "upi": "upi"
    }
    return mapping.get(t, None)

def main():
    print("[*] Loading ground truth...")
    with open("ground_truth.json") as f:
        gt = json.load(f)

    # Build GT lookup maps
    gt_instances = set()
    gt_normalized = {} # (path, type, norm_val) -> original (path, type, value)
    
    for pf in gt["pii_files"]:
        gt_path = pf["path"]
        for inst in pf["pii_instances"]:
            gt_type = inst["pii_type"]
            gt_val = inst["value"]
            gt_instances.add((gt_path, gt_type, gt_val))
            
            norm_val = clean_val(gt_val, gt_type)
            gt_normalized[(gt_path, gt_type, norm_val)] = (gt_path, gt_type, gt_val)

    bait_paths = set(b["path"] for b in gt["bait_files"])
    clean_paths = set(c["path"] for c in gt["clean_files"])

    print("[*] Running Black Sentinel Scan...")
    engine = ScanEngine()
    summary = engine.scan(r"C:\ThisPCTest")
    
    findings = []
    for r in summary.results:
        # Convert absolute path to ground truth path format
        actual_path = r.metadata.get("parent") or r.file_path
        path_parts = Path(actual_path).parts
        if "ThisPCTest" in path_parts:
            idx = path_parts.index("ThisPCTest")
            rel_path = "/".join(path_parts[idx+1:])
        else:
            rel_path = actual_path.replace("C:\\ThisPCTest\\", "C_Drive/").replace("\\", "/")
        
        for f in r.findings:
            pii_type = map_scanner_type_to_gt(f)
            if pii_type is None:
                continue
            val = f.get("raw_value") or f.get("matched_value") or ""
            
            findings.append({
                "path": rel_path,
                "pii_type": pii_type,
                "value": val
            })

    print(f"[*] Scanner produced {len(findings)} findings.")

    # Scoring
    tp = 0
    fp = 0
    matched_gt = set() # Keep track of which original GT instances were successfully matched
    
    for f in findings:
        f_path = f["path"]
        f_type = f["pii_type"]
        f_val = f["value"]
        
        # Try exact match first
        exact_key = (f_path, f_type, f_val)
        if exact_key in gt_instances:
            tp += 1
            matched_gt.add(exact_key)
        else:
            # Try normalized match
            norm_val = clean_val(f_val, f_type)
            norm_key = (f_path, f_type, norm_val)
            if norm_key in gt_normalized:
                orig_key = gt_normalized[norm_key]
                tp += 1
                matched_gt.add(orig_key)
            else:
                # Check if false positive
                if f_path in bait_paths or f_path in clean_paths:
                    fp += 1
                else:
                    fp += 1

    # Recall is based on unique GT instances detected
    tp_unique = len(matched_gt)
    total_gt = len(gt_instances)
    fn_unique = total_gt - tp_unique
    
    # Calculate Precision and Recall
    # Exact prompt scoring:
    tp_exact = 0
    fp_exact = 0
    for f in findings:
        exact_key = (f["path"], f["pii_type"], f["value"])
        if exact_key in gt_instances:
            tp_exact += 1
        elif f["path"] in bait_paths or f["path"] in clean_paths:
            fp_exact += 1
        else:
            fp_exact += 1
            
    fn_exact = total_gt - tp_exact
    
    print("\n=== EXACT MATCH METRICS (per prompt script) ===")
    p_ex = tp_exact / (tp_exact + fp_exact) if (tp_exact + fp_exact) > 0 else 0
    r_ex = tp_exact / total_gt if total_gt > 0 else 0
    f1_ex = 2 * p_ex * r_ex / (p_ex + r_ex) if (p_ex + r_ex) > 0 else 0
    print(f"TP={tp_exact}, FP={fp_exact}, FN={fn_exact}")
    print(f"Precision={p_ex:.1%}, Recall={r_ex:.1%}, F1={f1_ex:.1%}")

    print("\n=== NORMALIZED MATCH METRICS ===")
    p_norm = tp_unique / (tp_unique + fp) if (tp_unique + fp) > 0 else 0
    r_norm = tp_unique / total_gt if total_gt > 0 else 0
    f1_norm = 2 * p_norm * r_norm / (p_norm + r_norm) if (p_norm + r_norm) > 0 else 0
    print(f"TP_unique={tp_unique}, FP={fp}, FN_unique={fn_unique}")
    print(f"Precision={p_norm:.1%}, Recall={r_norm:.1%}, F1={f1_norm:.1%}")

    print("\n=== MISSED GT INSTANCES (False Negatives) ===")
    missed = gt_instances - matched_gt
    # Sort by path and type for readability
    for path, pii_type, value in sorted(missed, key=lambda x: (x[0], x[1])):
        print(f"Missed: {path} | {pii_type} | {value!r}")

    print("\n=== FALSE POSITIVES (FPs) ===")
    fps = []
    for f in findings:
        f_path = f["path"]
        f_type = f["pii_type"]
        f_val = f["value"]
        
        exact_key = (f_path, f_type, f_val)
        if exact_key not in gt_instances:
            norm_val = clean_val(f_val, f_type)
            norm_key = (f_path, f_type, norm_val)
            if norm_key not in gt_normalized:
                fps.append(f)
                
    for f in sorted(fps, key=lambda x: (x["path"], x["pii_type"])):
        print(f"FP: {f['path']} | {f['pii_type']} | {f['value']!r}")

if __name__ == "__main__":
    main()
