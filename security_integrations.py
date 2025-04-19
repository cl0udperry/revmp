import requests
import logging
import re
import warnings
import json

# Module for integrations with Coverity and Blackduck security scanning tools
# Uses credentials and settings from config.py for API access

try:
    import config
except ImportError:
    raise ImportError("The config.py module is required")

warnings.filterwarnings("ignore")
logger = logging.getLogger(__name__)
proxies = {
    "http": "",
    "https": "",
}

def blackduck_auth():
    # bearerToken and csrf_token for Blackduck authentication
    url = f"{config.blackduckBaseUrl}/api/tokens/authenticate"
    payload = {}
    headers = {'Authorization': config.blackduckAPI}
    response = requests.request("POST", url, headers = headers, data = payload, verify = False, proxies = proxies)
    bearerToken = json.loads(response.text)["bearerToken"]
    bearerToken = 'Bearer' + bearerToken
    csrf_token = response.headers.get('X-CSRF-TOKEN')
    return bearerToken, csrf_token

def get_blackduck_vulnerabilities(blackduck_url):
    # Retrieve vulnerabilities from a Blackduck project version
    try:
        # Parse the Blackduck url to extract projectId and versionId
        match = re.search(r"/projects/([^/]+)/versions/([^/]+)", blackduck_url)
        if not match: 
            logger.error("Invalid Blackduck URL format: %s, blackduck_url")
            return[]
        project_id, version_id = match.group(1), match.group(2)

        #Base URL for API calls
        base_url = config.blackduckBaseUrl
        vulnerability_url = f"{base_url}/api/projects/{project_id}/versions/{version_id}/vulnerability-bom/?limit=200"
        bearerToken, csrf_token = blackduck_auth()
        headers = {
            'Authorization': bearerToken,
            'X-XSRF-TOKEN': csrf_token
        }
        logger.info(f"Fetching Blackduck vulnerabilities for project {project_id}, version {version_id}")

        #Fetch Vulnerabilities
        response = requests.get(vulnerability_url, headers=headers, verify=False, proxies=proxies)
        response.raise_for_status()
        vulnerability_data = response.json()

        #Extract vuln details
        vulnerabilities = {}
        for item in vulnerability_data.get('items', []):
            vulnerabilities_url = next((link.get("href") for link in item.get("meta", {}).get("links", []) if link.get("rel") == "vulnerabilities"), None)

            if vulnerabilities_url:
                response = requests.get(vulnerability_url, headers=headers, verify=False, proxies=proxies)
                response.raise_for_status()
                vulnerabilities_data = response.json()

                for vulnerability in vulnerabilities_data.get("items", []):
                    bdsa_id = vulnerability.get("id")

                    vuln_info = {
                        "bdsa_id": bdsa_id,
                        "component_name": item.get("componentName"),
                        "component_version": item.get("componentVersionName"),
                        "severity": vulnerability.get("cvss3", {}).get("severity"),
                        "upgrade_guidance_url": next((link.get("href") for link in item.get("_meta", {}).get("links", []) if link.get("rel") == "upgrade-guidance"), None),
                        "remediationStatus": vulnerability.get("remediationStatus"),
                        "comment": vulnerability.get("comment")
                    }

                    # Call Upgrade Guidance API for remediation info
                    if vuln_info["upgrade_guidance_url"]:
                        remediation_info = get_blackduck_remediation(vuln_info["upgrade_guidance_url"], headers)
                        vuln_info.update(remediation_info)

                    if vuln_info["bdsa_id"] is not None:
                        vulnerabilities[bdsa_id] = vuln_info
        logger.info(f"Found {len(vulnerabilities)} vulnerabiltiies in Blackduck project version")

        return list(vulnerabilities.values())
    except requests.RequestException as req_error:
        logger.error("Failed to retrieve Blackduck vulnerabilities %s", req_error)
        return []
    except Exception as e:
        logger.exception("An error occurred while retrieveing Blackduck vulnerabilities %s", e)
        return []

def get_blackduck_remediation(upgrade_guidance_url, headers):
    # Fetches upgrade/remediation details for a specific Blackduck vulnerability
    try:
        logger.info(f"Fetching remediation details from {upgrade_guidance_url}")
        bearerToken, csrf_token = blackduck_auth()
        headers = {
            'Authorization': bearerToken,
            'X-XSRF-TOKEN': csrf_token
        }
        response = requests.get(upgrade_guidance_url, headers=headers, verify=False, proxies=proxies)
        response.raise_for_status()
        remediation_data = response.json()

        return {
            "upgrade_recommendation": remediation_data.get("upgradeGuidance",{}).get("upgradeRecommendation", "None"),
        }
    except requests.RequestException as req_err:
        logger.warning("Failed to retrieve remediation details from %s: %s", upgrade_guidance_url, req_err)
        return {"remediation_status": "Unknown", "upgrade_recommendation": "None"}
    
def get_blackduck_vuln_details(vuln_url, headers):
    # Fetches detailed Blackduck vulnerability data, including BDSA ID and Severity

    try:
        logger.info(f"Fetching detailed vulnerability info from {vuln_url}")
        response = requests.get(vuln_url, headers=headers, verify=False, proxies=proxies)
        response.raise_for_status()
        vuln_data = response.json()

        return {
            "bdsa_id": vuln_data.get("id"),
            "severity": vuln_data.get("cvss", {}).get("severity", "Unknown")
        }
    except requests.RequestException as req_err:
        logger.warning("Failed to retrieve Blackduck vulnerability details from %s: %s", vuln_url, req_err)
        return {"bdsa_id": "Unknown", "severity":"None"}
    
def get_coverity_vulnerabilities(snapshot_id):
    # Retrieve vulnerabilities from Coverity Snapshot
    try:
        base_url = config.coverityBaseUrl 
        snapshot_url = f"{base_url}/api/v2/snapshots/{snapshot_id}"
        headers = {'Authorization': config.coverityBasicAuthString}
        logger.info(f"Fetching Coverity snapshot details for snapshotID {snapshot_id}")
        response = requests.get(snapshot_url, headers=headers, verify=False, proxies=proxies)
        response.raise_for_status()
        snapshot_data = response.json()

        #Extract stream ID from snapshot details
        stream_id = snapshot_data.get("streamId")
    
        if not stream_id:
            logger.error("Stram ID not found for snapshot ID %s", snapshot_id)
            return []
        
        #Fetch issues from Coverity Search API
        search_url = f"{base_url}/api/v2/issues/search?includeColumnLavels=true&rowCount=10000"
        search_payload = {
            "filter": [
                {
                    "columnKey": "streams",
                    "matchMode": "oneOrMoreMatch",
                    "matchers": [
                        {"class": "Stream", "id": stream_id, "type": "idMatcher"}
                    ]
                }
            ],
            "snapshotScope": {
                "show": {
                    "scope": snapshot_id,
                    "includeOutdatedSnapshots": False
                }
            },
            "columns": ["displayImpact", "displayType", "cid", "status"]
        }
        logger.info(f"Searching Coverity issues for stream {stream_id} and snapshot {snapshot_id}")
        search_resp = requests.post(search_url)
        search_resp.raise_for_status()
        results = search_resp.json()

        #Extract issues from response
        issues = results.get('rows', [])

        #Filter only "New" issues
        new_issues = []
        for issue in issues:
            issue_dict = {}
            for item in issue:
                issue_dict[item.get('key')] =  item.get('value')
            if issue_dict.get('status', '').lower() == "new":
                if 'cid' in issue_dict:
                    new_issues.append(issue_dict)

        logger.info(f"Found {len(new_issues)} new issues in Coverity snapshot {snapshot_id}")

        return new_issues
    except requests.RequestException as req_err:
        print(f"Error: {req_err}")
        logger.error("Failed to retrieve Coverity vulnerabilities for snapshot %s: %s, snapsho_id, req_err")
        return[]
    except Exception as e:
        logger.exception("An error occurred while retrieving Coverity vulnerabilities fr snapshot %s: %s", snapshot_id, e)
        return []