import os
import requests
import time
import pandas as pd

def __extract_repository_name(df: pd.DataFrame) -> pd.DataFrame:
    df['repository_name'] = df['repository'].apply(lambda x: x.get('name') if isinstance(x, dict) else None)
    return df

def format_sast_csv(sast_findings: list, output_file: str):
    df = pd.DataFrame(sast_findings)
    df = __extract_repository_name(df)
    
    columns = [
        'id',
        'ref',
        'repository_name',
        'line_of_code_url',
        'status',
        'confidence',
        'rule_name',
        'rule_message',
        'severity'
    ]
    
    df = df[columns]
    df.to_csv(output_file, index=False)
    return df

def format_sca_csv(sca_findings: list, output_file: str):
    df = pd.DataFrame(sca_findings)
    df = __extract_repository_name(df)
    df['epss_score'] = df['epss_score'].apply(lambda x: x.get('score') if isinstance(x, dict) else None)
    df['epss_percentile'] = df['epss_score'].apply(lambda x: x.get('percentile') if isinstance(x, dict) else None)
    
    df['fix_recommendations'] = df['fix_recommendations'].apply(
        lambda x: ';'.join([f"{rec.get('package', '')}:{rec.get('version', '')}" for rec in x]) 
        if isinstance(x, list) else None
    )
    
    df['package'] = df['found_dependency'].apply(lambda x: x.get('package') if isinstance(x, dict) else None)
    df['version'] = df['found_dependency'].apply(lambda x: x.get('version') if isinstance(x, dict) else None)
    df['ecosystem'] = df['found_dependency'].apply(lambda x: x.get('ecosystem') if isinstance(x, dict) else None)
    df['transitivity'] = df['found_dependency'].apply(lambda x: x.get('transitivity') if isinstance(x, dict) else None)
    df['lockfile_line_url'] = df['found_dependency'].apply(lambda x: x.get('lockfile_line_url') if isinstance(x, dict) else None)
    
    columns = [
        'id',
        'ref',
        'repository_name',
        'line_of_code_url',
        'status',
        'confidence',
        'rule_name',
        'rule_message',
        'severity',
        'vulnerability_identifier',
        'reachability',
        'reachable_condition',
        'epss_score',
        'epss_percentile',
        'fix_recommendations',
        'package',
        'version',
        'ecosystem',
        'transitivity',
        'lockfile_line_url'
    ]
    
    df = df[columns]
    df.to_csv(output_file, index=False)
    return df

def format_secrets_csv(secret_findings: list, output_file: str):
    df = pd.DataFrame(secret_findings)
    df = __extract_repository_name(df)
    
    columns = [
        'id',
        'type',
        'findingPathUrl',
        'repository_name',
        'ref',
        'refUrl',
        'severity',
        'confidence',
        'validationState',
        'status'
    ]
    
    df = df[columns]
    
    df.to_csv(output_file, index=False)
    return df

class SemgrepClient:
    def __init__(self, api_key: str):
        self.base_url = "https://semgrep.dev/api/v1"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        }

    def get_deployment(self):
        deployment_response = self.__make_request_with_retry("GET", f"{self.base_url}/deployments")
        return deployment_response["deployments"][0]

    def get_sast_findings(self, 
                          deployment_slug: str,
                          dedup: bool = True,
                          status: str = "open"):
        findings = self.__get_findings(deployment_slug, "sast", dedup=dedup, status=status)
        return findings
    
    def get_sca_findings(self,
                         deployment_slug: str,
                         dedup: bool = True,
                         status: str = "open"):
        findings = self.__get_findings(deployment_slug, "sca", dedup=dedup, status=status)
        return findings
    
    def get_secret_findings(self,
                            deployment_id: int,
                            status: str | None = "FINDING_STATUS_OPEN"):
        cursor = None
        while True:
            params = {
                "limit": 1000,
            }
            if cursor:
                params["cursor"] = cursor
            if status:
                params["status"] = status

            response = self.__make_request_with_retry("GET", f"{self.base_url}/deployments/{deployment_id}/secrets", params)
            findings = response.get("findings", [])
            if len(findings) == 0:
                break
            yield findings
            cursor = response.get("cursor", None)
            if not cursor:
                break
            

    def __get_findings(self,
                       deployment_slug: str,
                       issue_type: str,
                       dedup: bool = True,
                       status: str = "open"):
        page = 0
        while True:
            params = {
                "page": page,
                "issue_type": issue_type,
                "page_size": 1000,
            }
            if dedup:
                params["dedup"] = dedup
            if status:
                params["status"] = status

            findings_response = self.__make_request_with_retry("GET", f"{self.base_url}/deployments/{deployment_slug}/findings", params)
            findings = findings_response.get("findings", [])
            if len(findings) == 0:
                break
            yield findings
            page += 1

    def __make_request_with_retry(self, method: str, url: str, params: dict = None, data: dict = None):
        if data:
            headers = self.headers
            headers["Content-Type"] = "application/json"
        else:
            headers = self.headers

        for i in range(5):
            try:
                response = requests.request(method, url, params=params, headers=headers, data=data)
                response.raise_for_status()
                return response.json()
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(1)

        return None

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
