import json
import time
import requests
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import ResourceNotFoundError
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED
from SiemplifyUtils import output_handler
from config import AZ_TENANT_ID, AZ_CLIENT_ID, AZ_CLIENT_SECRET, KEY_VAULT_NAME, SECRET_NAMES

SUPPORTED_ENTITIES = [
    EntityTypes.FILEHASH, EntityTypes.ADDRESS, EntityTypes.DOMAIN, EntityTypes.URL
]

def get_parsed_entities(target_entities, logger):
    result = {"SHA256": [], "SHA1": [], "MD5": [], "IP": [], "Domain": [], "URL": []}
    for entity in target_entities:
        entity_value = entity.identifier.strip().lower()

        if entity.entity_type == EntityTypes.ADDRESS:
            result["IP"].append(entity_value)
        elif entity.entity_type == EntityTypes.DOMAIN:
            result["Domain"].append(entity_value)
        elif entity.entity_type == EntityTypes.URL:
            result["URL"].append(entity_value)
        elif entity.entity_type == EntityTypes.FILEHASH:
            if len(entity_value) == 40:
                result["SHA1"].append(entity_value)
            elif len(entity_value) == 32:
                result["MD5"].append(entity_value)
            elif len(entity_value) == 64:
                logger.info(f"Skipping unsupported hash type (SHA256): {entity_value}")
        else:
            logger.info(f"Skipping unsupported entity type: {entity.entity_type}")
    return result

def parse_secret(secret_value):
    if 'secret=' not in secret_value or 'id=' not in secret_value:
        return None, None
    if 'secret=' in secret_value and 'id=' in secret_value and 'secret=' not in secret_value.split('id=')[-1]:
        secret_value = secret_value.replace('secret=', ' secret=')
    try:
        parts = dict(kv.split('=', 1) for kv in secret_value.strip().split())
        return parts.get("id"), parts.get("secret")
    except Exception:
        return None, None

def is_valid_url_ioc(url):
    return not url.endswith('=')

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.LOGGER.info("------ Harmony Add IOC Script Started ------")

    vault_url = f"https://{KEY_VAULT_NAME}.vault.azure.net"
    credential = ClientSecretCredential(AZ_TENANT_ID, AZ_CLIENT_ID, AZ_CLIENT_SECRET)
    secret_client = SecretClient(vault_url=vault_url, credential=credential)

    parsed_entities = get_parsed_entities(siemplify.target_entities, siemplify.LOGGER)
    invalid_iocs_seen = set()
    ioc_data = []

    for entity_type, values in parsed_entities.items():
        for value in values:
            original_value = value
            if entity_type == "URL":
                if value.startswith("https://"):
                    value = value.replace("https://", "http://", 1)
                if not is_valid_url_ioc(value):
                    if value not in invalid_iocs_seen:
                        siemplify.LOGGER.info(f"Skipping invalid URL IOC: {value}")
                        invalid_iocs_seen.add(value)
                    continue
            ioc_data.append({
                "type": entity_type,
                "value": value,
                "comment": "Added from Chronicle SOAR"
            })

    if not ioc_data:
        siemplify.LOGGER.info("No supported IOC entities found.")
        siemplify.end("No supported entities to add as IOC.", False, EXECUTION_STATE_COMPLETED)
        return

    results = {}

    for secret_name in SECRET_NAMES:
        siemplify.LOGGER.info(f"Processing secret: {secret_name}")
        try:
            raw_secret = secret_client.get_secret(secret_name).value
            client_id, client_secret = parse_secret(raw_secret)
            if not client_id or not client_secret:
                results[secret_name] = "Invalid secret format"
                continue

            auth_payload = {'clientId': client_id, 'accessKey': client_secret}
            headers = {'Content-Type': 'application/json'}
            auth_response = requests.post(
                'https://cloudinfra-gw.portal.checkpoint.com/auth/external',
                json=auth_payload, headers=headers
            )
            if auth_response.status_code != 200:
                results[secret_name] = f"Auth failed: {auth_response.text}"
                continue

            bearer_token = auth_response.json().get('data', {}).get('token')
            session_headers = {
                'Authorization': f'Bearer {bearer_token}',
                'Content-Type': 'application/json'
            }
            session_response = requests.post(
                'https://cloudinfra-gw.portal.checkpoint.com/app/endpoint-web-mgmt/harmony/endpoint/api/v1/session/login/cloud',
                headers=session_headers, json={}
            )
            if session_response.status_code != 201:
                results[secret_name] = f"Session login failed: {session_response.text}"
                continue

            api_token = session_response.json().get('apiToken')
            ioc_headers = {
                'Authorization': f'Bearer {bearer_token}',
                'x-mgmt-api-token': api_token,
                'Content-Type': 'application/json',
                'x-mgmt-run-as-job': 'off'
            }
            ioc_response = requests.post(
                'https://cloudinfra-gw.portal.checkpoint.com/app/endpoint-web-mgmt/harmony/endpoint/api/v1/ioc/create',
                headers=ioc_headers, json=ioc_data
            )

            if ioc_response.status_code == 200:
                results[secret_name] = "✅ IOCs added successfully"
            else:
                results[secret_name] = f"❌ IOC creation failed: {ioc_response.status_code} - {ioc_response.text}"

        except ResourceNotFoundError:
            results[secret_name] = "❌ Secret not found in Azure Key Vault"
        except Exception as e:
            results[secret_name] = f"❌ Exception: {str(e)}"

        time.sleep(3)

    output_message = "\n".join(f"{k}: {v}" for k, v in results.items())
    siemplify.end(output_message, True, EXECUTION_STATE_COMPLETED)

if __name__ == '__main__':
    main()
