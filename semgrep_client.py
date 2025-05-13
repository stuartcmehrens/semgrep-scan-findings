import requests
import time

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
