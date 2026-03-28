#!/usr/bin/env python3
import sys
import json
import datetime

def main():
    if len(sys.argv) < 2:
        print("Usage: generate_vex.py <trivy-report.json>")
        sys.exit(1)
        
    try:
        with open(sys.argv[1], 'r') as f:
            report = json.load(f)
    except Exception as e:
        print(f"Error reading report: {e}")
        sys.exit(1)
        
    vex = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://svveec0d3.github.io/vex/{datetime.datetime.utcnow().isoformat()}Z",
        "author": "secure-deploy-pipeline",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "version": 1,
        "statements": []
    }
    
    results = report.get('Results', [])
    for res in results:
        vulns = res.get('Vulnerabilities', [])
        for vul in vulns:
            # If our pipeline flagged it as NOT reachable or NOT requiring manual review via KEV/EPSS
            # We declare it as "not_affected" with justification "inline_mitigation_already_exist" or "vulnerable_code_not_in_execute_path"
            vuln_id = vul.get("VulnerabilityID")
            pkg_name = vul.get("PkgName")
            gate_decision = vul.get("GateDecision")
            reachable = vul.get("Reachability", "Unknown")
            
            if reachable == "No":
                statement = {
                    "vulnerability": {"name": vuln_id},
                    "products": [{"@id": f"pkg:docker/n8nio/n8n"}],
                    "status": "not_affected",
                    "justification": "vulnerable_code_not_in_execute_path",
                    "impact_statement": f"{pkg_name} is included in the image but Tracee smoke test confirms it is never reached during operation."
                }
                vex["statements"].append(statement)
            elif gate_decision == "AUTO_ALLOWED":
                statement = {
                    "vulnerability": {"name": vuln_id},
                    "products": [{"@id": f"pkg:docker/n8nio/n8n"}],
                    "status": "under_investigation",
                    "impact_statement": f"{pkg_name} auto-promoted since it lacks KEV evidence, high EPSS, or aged exposure."
                }
                vex["statements"].append(statement)
                
    print(json.dumps(vex, indent=2))

if __name__ == "__main__":
    main()
