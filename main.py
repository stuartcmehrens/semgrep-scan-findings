import os
from semgrep_client import SemgrepClient
from utils import format_sast_csv, format_sca_csv, format_secrets_csv

semgrep_api_key = os.getenv("SEMGREP_API_KEY")
if not semgrep_api_key:
    raise ValueError("SEMGREP_API_KEY is not set")

def main():
    semgrep_client = SemgrepClient(api_key=semgrep_api_key)
    deployment = semgrep_client.get_deployment()
    print(deployment)

    sast_findings = []
    for page_num, finding_page in enumerate(semgrep_client.get_sast_findings(deployment.get("slug"))):
        print(f"Page {page_num}: findings count{len(finding_page)}")
        sast_findings.extend(finding_page)

    format_sast_csv(sast_findings, "data/sast_findings.csv")

    sca_findings = []
    for page_num, finding_page in enumerate(semgrep_client.get_sca_findings(deployment.get("slug"))):
        print(f"Page {page_num}: {len(finding_page)}")
        sca_findings.extend(finding_page)

    format_sca_csv(sca_findings, "data/sca_findings.csv")

    secret_findings = []
    for page_num, finding_page in enumerate(semgrep_client.get_secret_findings(deployment.get("id"))):
        print(f"Page {page_num}: {len(finding_page)}")
        secret_findings.extend(finding_page)

    format_secrets_csv(secret_findings, "data/secret_findings.csv")

if __name__ == "__main__":
    main()
