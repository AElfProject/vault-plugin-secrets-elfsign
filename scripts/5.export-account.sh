#!/usr/bin/env bash

export VAULT_ADDR='http://127.0.0.1:8200'
curl -H "X-Vault-Request: true" \
-H "X-Vault-Token: $(vault print token)" \
$VAULT_ADDR/v1/aelf/export/accounts/$1 | jq
