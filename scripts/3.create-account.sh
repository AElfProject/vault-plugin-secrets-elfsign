#!/usr/bin/env bash

export VAULT_ADDR='http://127.0.0.1:8200'
curl -X PUT \
-H "X-Vault-Request: true" \
-H "X-Vault-Token: $(vault print token)" \
-d '{}' $VAULT_ADDR/v1/aelf/accounts
