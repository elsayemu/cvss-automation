import requests
import json
import boto3
import sys
import subprocess
from datetime import datetime

# Try to import cvss, install if missing
try:
    from cvss import CVSS3
except ImportError:
    print("cvss package not found. Installing...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'cvss'])
        from cvss import CVSS3
        print("cvss package installed successfully.")
    except Exception as e:
        print(f"Failed to install cvss package: {e}")
        print("Please install manually: pip install cvss")
        sys.exit(1)

# NVD API Key
NVD_API_KEY = ''

# AWS Credentials
AWS_ACCESS_KEY_ID = ''
AWS_SECRET_ACCESS_KEY = ''
AWS_REGION = ''

LOG_PATH = '/home/ubuntu/wazuh_test.log'

def get_cve_details(cve_id):
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
    headers = {'apiKey': NVD_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        try:
            return response.json()['vulnerabilities'][0]['cve']
        except (KeyError, IndexError):
            return None
    else:
        return None

def get_cvss_vectors(cve_data):
    cvss_vectors = {}
    if 'metrics' in cve_data:
        if 'cvssMetricV4' in cve_data['metrics']:
            for metric in cve_data['metrics']['cvssMetricV4']:
                if metric['cvssData']['vectorString']:
                    cvss_vectors['CVSS v4.0'] = {
                        'vector': metric['cvssData']['vectorString'],
                        'base_score': metric['cvssData'].get('baseScore', 'Not available')
                    }
        if 'cvssMetricV31' in cve_data['metrics']:
            for metric in cve_data['metrics']['cvssMetricV31']:
                if metric['cvssData']['vectorString']:
                    cvss_vectors['CVSS v3.1'] = {
                        'vector': metric['cvssData']['vectorString'],
                        'base_score': metric['cvssData'].get('baseScore', 'Not available')
                    }
        if 'cvssMetricV30' in cve_data['metrics']:
            for metric in cve_data['metrics']['cvssMetricV30']:
                if metric['cvssData']['vectorString']:
                    cvss_vectors['CVSS v3.0'] = {
                        'vector': metric['cvssData']['vectorString'],
                        'base_score': metric['cvssData'].get('baseScore', 'Not available')
                    }
        if 'cvssMetricV2' in cve_data['metrics']:
            for metric in cve_data['metrics']['cvssMetricV2']:
                if metric['cvssData']['vectorString']:
                    cvss_vectors['CVSS v2.0'] = {
                        'vector': metric['cvssData']['vectorString'],
                        'base_score': metric['cvssData'].get('baseScore', 'Not available')
                    }
    return cvss_vectors

def get_newest_cvss_vector(cvss_vectors):
    if cvss_vectors:
        def extract_version(version_str):
            parts = version_str.split(' ')
            if len(parts) > 1:
                version = parts[1].replace('v', '')
                major, minor = version.split('.')
                return (int(major), int(minor))
            else:
                return (0, 0)
        newest_version = max(cvss_vectors.keys(), key=extract_version)
        return newest_version, cvss_vectors[newest_version]
    else:
        return None, None

def get_all_vulnerabilities(es_url, username, password):
    from requests.auth import HTTPBasicAuth
    try:
        session = requests.Session()
        session.auth = HTTPBasicAuth(username, password)
        session.verify = False
        session.headers.update({'Content-Type': 'application/json'})
        url = f'{es_url}/wazuh-states-vulnerabilities-*/_search'
        params = {'size': 1000}
        response = session.get(url, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to retrieve data. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return None
    except Exception as e:
        print(f"Error connecting to Elasticsearch: {e}")
        return None

def get_instance_tags_by_name(agent_name):
    ec2 = boto3.resource(
        'ec2',
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
    filters = [{'Name': 'tag:Name', 'Values': [agent_name]}]
    instances = ec2.instances.filter(Filters=filters)
    tags_list = []
    for instance in instances:
        tags = {tag['Key']: tag['Value'] for tag in instance.tags} if instance.tags else {}
        tags_list.append({'InstanceId': instance.id, 'Tags': tags})
    return tags_list

def calculate_enhanced_cvss_score(enhanced_vector):
    try:
        cvss_obj = CVSS3(enhanced_vector)
        scores = cvss_obj.scores()
        return scores[2] if len(scores) > 2 and scores[2] is not None else scores[0]
    except Exception:
        return None

def build_tag_string(tags):
    order = ['CR', 'AR', 'IR']
    tag_strs = []
    for tag in order:
        value = tags.get(tag, 'Low')
        if value.upper().startswith("H"):
            value_str = "High"
        elif value.upper().startswith("M"):
            value_str = "Medium"
        else:
            value_str = "Low"
        tag_strs.append(f"{tag}:{value_str}")
    return " ".join(tag_strs)

def append_vulnerability_entry(entry, log_path=LOG_PATH):
    with open(log_path, 'a') as f:
        f.write(json.dumps(entry) + '\n')

def process_and_log_vulnerabilities(vulnerability_data):
    for hit in vulnerability_data['hits']['hits']:
        agent_name = hit['_source']['agent']['name']
        cve_id = hit['_source']['vulnerability']['id']
        base_score = hit['_source']['vulnerability']['score']['base']
        cve_details = get_cve_details(cve_id)
        instance_tags = get_instance_tags_by_name(agent_name)
        tag_values = {"CR": "L", "AR": "L", "IR": "L"}
        if instance_tags:
            for instance in instance_tags:
                tags = instance['Tags']
                for tag in tag_values:
                    if tag in tags:
                        val = tags[tag].strip().upper()
                        if val.startswith("H"):
                            tag_values[tag] = "H"
                        elif val.startswith("M"):
                            tag_values[tag] = "M"
                        else:
                            tag_values[tag] = "L"
                tag_str = build_tag_string({k: tags.get(k, tag_values[k]) for k in tag_values})
                justification_parts = []
                for tag, meaning in [("CR", "Confidentiality Requirement"), ("AR", "Availability Requirement"), ("IR", "Integrity Requirement")]:
                    level = tag_values[tag]
                    if level == "H":
                        justification_parts.append(f"{meaning} is High")
                    elif level == "M":
                        justification_parts.append(f"{meaning} is Medium")
                    else:
                        justification_parts.append(f"{meaning} is Low")
                justification = "Score adjusted due to: " + ", ".join(justification_parts)

                entry = {
                    "Agent Name": agent_name,
                    "EC2 InstanceID": instance['InstanceId'],
                    "Tags": tag_str,
                    "CVE ID": cve_id,
                    "Base Score": str(base_score),
                    "Justification": justification
                }
                if cve_details:
                    cvss_vectors = get_cvss_vectors(cve_details)
                    _, newest_cvss = get_newest_cvss_vector(cvss_vectors)
                    if newest_cvss:
                        enhanced_cvss = (
                            f"{newest_cvss['vector']}/CR:{tag_values['CR']}/IR:{tag_values['IR']}/AR:{tag_values['AR']}"
                        )
                        entry["Enhanced CVSS Vector"] = enhanced_cvss
                        enhanced_score = calculate_enhanced_cvss_score(enhanced_cvss)
                        entry["Enhanced CVSS Score"] = float(enhanced_score) if enhanced_score is not None else None
                    else:
                        entry["Enhanced CVSS Vector"] = None
                        entry["Enhanced CVSS Score"] = None
                else:
                    entry["Enhanced CVSS Vector"] = None
                    entry["Enhanced CVSS Score"] = None
                append_vulnerability_entry(entry)
        else:
            tag_str = build_tag_string(tag_values)
            justification_parts = []
            for tag, meaning in [("CR", "Confidentiality Requirement"), ("AR", "Availability Requirement"), ("IR", "Integrity Requirement")]:
                level = tag_values[tag]
                if level == "H":
                    justification_parts.append(f"{meaning} is High")
                elif level == "M":
                    justification_parts.append(f"{meaning} is Medium")
                else:
                    justification_parts.append(f"{meaning} is Low")
            justification = "Score adjusted due to: " + ", ".join(justification_parts)

            entry = {
                "Agent Name": agent_name,
                "EC2 InstanceID": None,
                "Tags": tag_str,
                "CVE ID": cve_id,
                "Base Score": str(base_score),
                "Enhanced CVSS Vector": None,
                "Enhanced CVSS Score": None,
                "Justification": justification
            }
            append_vulnerability_entry(entry)

def main():
    es_url = 'https://localhost:9200'
    username = ''
    password = ''
    vulnerability_data = get_all_vulnerabilities(es_url, username, password)
    if vulnerability_data:
        process_and_log_vulnerabilities(vulnerability_data)
        print(f"Entries appended to: {LOG_PATH}")
    else:
        print("No vulnerability data retrieved.")

if __name__ == '__main__':
    main()
