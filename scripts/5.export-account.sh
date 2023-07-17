#!/usr/bin/env bash

export VAULT_ADDR='http://127.0.0.1:8200'
vault read /aelf/export/accounts/$1 ""
