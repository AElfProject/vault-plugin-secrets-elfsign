#!/usr/bin/env python3
import logging
import json
import hvac
logging.basicConfig(format='%(message)s', level=logging.INFO)

client = hvac.Client(url="http://127.0.0.1:8200")

key_admin_policy = """
path "/aelf/accounts" {
  capabilities = ["update", "list"]
}
path "/aelf/accounts/*" {
  capabilities = ["create", "update", "read"]
}
"""

key_store_manager_policy = """
path "/aelf/accounts" {
  capabilities = ["list"]
}
path "/aelf/accounts/*" {
  capabilities = ["read"]
}
path "/aelf/export/accounts/*" {
  capabilities = ["read"]
}
"""

key_store_password_manager_policy = """
path "/aelf/accounts" {
  capabilities = ["list"]
}
path "/aelf/export/passwords/*" {
  capabilities = ["read"]
}
"""

verifier_deployer_policy = """
path "/aelf/accounts/*" {
  capabilities = ["read"]
}
path "/aelf/export/accounts/*" {
  capabilities = ["read"]
}
path "/aelf/export/passwords/*" {
  capabilities = ["read"]
}
"""

client.sys.create_or_update_policy(
    name="key-admin",
    policy=key_admin_policy
)
client.sys.create_or_update_policy(
    name="key-store-manager",
    policy=key_store_manager_policy
)
client.sys.create_or_update_policy(
    name="key-store-password-manager",
    policy=key_store_password_manager_policy
)
client.sys.create_or_update_policy(
    name="verifier-deployer",
    policy=verifier_deployer_policy
)

token_key_admin = client.auth.token.create(policies=['key-admin'], ttl='1h')
token_key_store_manager = client.auth.token.create(policies=['key-store-manager'], ttl='1h')
token_key_store_password_manager = client.auth.token.create(policies=['key-store-password-manager'], ttl='1h')
token_verifier_deployer = client.auth.token.create(policies=['verifier-deployer'], ttl='1h')


last_account_address = None

def demo(token):
    global last_account_address
    client.token = token['auth']['client_token']
    policy_name = (token['auth']['token_policies'][-1] + ' ' * 30)[:30]
    # Create key
    try:
        resp = client.write('/aelf/accounts')
        last_account_address = resp['data']['address']
        logging.info('%s created key of address %s' % (policy_name, resp['data']['address']))
    except:
        logging.error('%s FAILED to create key' % policy_name)
    # List accounts
    try:
        resp = client.list('/aelf/accounts')
        keys = resp['data']['keys']
        logging.info('%s listed key of %s addresses and last address is %s' % (policy_name, len(keys), keys[-1]))
    except:
        logging.error('%s FAILED to list account' % policy_name)
    # Read account
    try:
        resp = client.read('/aelf/accounts/%s' % last_account_address)
        logging.info('%s read account %s' % (policy_name, resp['data']))
    except:
        logging.error('%s FAILED to read account' % policy_name)
    # Export account
    try:
        resp = client.read('/aelf/export/accounts/%s' % last_account_address)
        logging.info('%s exported account %s' % (policy_name, json.dumps(resp['data'])[:50]+'...'))
    except:
        logging.error('%s FAILED to export account %s' % (policy_name, last_account_address))
    # Export password
    try:
        resp = client.read('/aelf/export/passwords/%s' % last_account_address)
        logging.info('%s exported password %s' % (policy_name, json.dumps(resp['data'])[:50]+'...'))
    except:
        logging.error('%s FAILED to export password for %s' % (policy_name, last_account_address))


if __name__ == "__main__":
    demo(token_key_admin)
    demo(token_key_store_manager)
    demo(token_key_store_password_manager)
    demo(token_verifier_deployer)
