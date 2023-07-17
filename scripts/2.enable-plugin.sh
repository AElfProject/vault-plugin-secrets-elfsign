#!/usr/bin/env bash

export VAULT_ADDR='http://127.0.0.1:8200'
vault secrets enable -path=aelf \
-description="AElf Signing Wallet" \
-plugin-name=elfsign plugin
