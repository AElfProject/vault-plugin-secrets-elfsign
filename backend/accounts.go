// Copyright © 2020 Kaleido
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/AElfProject/vault-plugin-secrets-elfsign/base58"
	"regexp"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Account is an Ethereum account
type Account struct {
	KeyStore  *encryptedKeyJSONV3 `json:"key_store"`
	PublicKey string              `json:"public_key"`
}

// AccountPassword is a password for the keystore
type AccountPassword struct {
	Address  string `json:"address"`
	Password string `json:"password"`
}

func paths(b *backend) []*framework.Path {
	return []*framework.Path{
		pathCreateAndList(b),
		pathReadAndDelete(b),
		pathExport(b),
		pathExportPassword(b),
	}
}

func (b *backend) listAccounts(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, "accounts/")
	if err != nil {
		b.Logger().Error("Failed to retrieve the list of accounts", "error", err)
		return nil, err
	}

	return logical.ListResponse(vals), nil
}

func (b *backend) createAccount(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	keyInput := data.Get("privateKey").(string)
	var privateKey *ecdsa.PrivateKey
	var err error

	if keyInput != "" {
		re := regexp.MustCompile("[0-9a-fA-F]{64}$")
		key := re.FindString(keyInput)
		if key == "" {
			b.Logger().Error("Input private key did not parse successfully", "privateKey", keyInput)
			return nil, fmt.Errorf("privateKey must be a 32-byte hexidecimal string")
		}
		privateKey, err = crypto.HexToECDSA(key)
		if err != nil {
			b.Logger().Error("Error reconstructing private key from input hex", "error", err)
			return nil, fmt.Errorf("Error reconstructing private key from input hex")
		}
	} else {
		privateKey, _ = crypto.GenerateKey()
	}

	defer ZeroKey(privateKey)

	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	sum1 := sha256.Sum256(publicKeyBytes)
	sum2 := sha256.Sum256(sum1[:])
	address := base58.EncodeCheck(sum2[:])
	publicKeyString := hex.EncodeToString(publicKeyBytes)

	ks, auth, err := ToKeyStore(privateKey)
	if err != nil {
		b.Logger().Error("Failed to get the keystore", "error", err)
		return nil, err
	}

	passwordPath := fmt.Sprintf("passwords/%s", address)

	passwordJSON := &AccountPassword{
		address,
		*auth,
	}

	pEntry, _ := logical.StorageEntryJSON(passwordPath, passwordJSON)
	err = req.Storage.Put(ctx, pEntry)
	if err != nil {
		b.Logger().Error("Failed to save the new account to storage", "error", err)
		return nil, err
	}
	accountPath := fmt.Sprintf("accounts/%s", address)
	accountJSON := &Account{
		KeyStore:  ks,
		PublicKey: publicKeyString,
	}

	entry, _ := logical.StorageEntryJSON(accountPath, accountJSON)
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		b.Logger().Error("Failed to save the new account to storage", "error", err)
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address": accountJSON.KeyStore.Address,
		},
	}, nil
}

func (b *backend) readAccount(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	address := data.Get("name").(string)
	b.Logger().Info("Retrieving account for address", "address", address)
	account, err := b.retrieveAccount(ctx, req, address)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, fmt.Errorf("Account does not exist")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address": account.KeyStore.Address,
		},
	}, nil
}

func (b *backend) exportAccount(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	address := data.Get("name").(string)
	b.Logger().Info("Retrieving account for address", "address", address)
	account, err := b.retrieveAccount(ctx, req, address)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, fmt.Errorf("Account does not exist")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"account": account,
		},
	}, nil
}

func (b *backend) exportPassword(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	address := data.Get("name").(string)
	b.Logger().Info("Retrieving account for address", "address", address)
	account, err := b.retrievePassword(ctx, req, address)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, fmt.Errorf("Account does not exist")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address":  account.Address,
			"password": account.Password,
		},
	}, nil
}

func (b *backend) deleteAccount(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	address := data.Get("name").(string)
	account, err := b.retrieveAccount(ctx, req, address)
	if err != nil {
		b.Logger().Error("Failed to retrieve the account by address", "address", address, "error", err)
		return nil, err
	}
	if account == nil {
		return nil, nil
	}
	if err := req.Storage.Delete(ctx, fmt.Sprintf("accounts/%s", account.KeyStore.Address)); err != nil {
		b.Logger().Error("Failed to delete the account from storage", "address", address, "error", err)
		return nil, err
	}
	return nil, nil
}

func (b *backend) retrieveAccount(ctx context.Context, req *logical.Request, address string) (*Account, error) {

	if err := b.validateAddress(address); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("accounts/%s", address)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		b.Logger().Error("Failed to retrieve the account by address", "path", path, "error", err)
		return nil, err
	}
	if entry == nil {
		// could not find the corresponding key for the address
		return nil, nil
	}
	var account Account
	_ = entry.DecodeJSON(&account)
	return &account, nil
}

func (b *backend) retrievePassword(ctx context.Context, req *logical.Request, address string) (*AccountPassword, error) {

	if err := b.validateAddress(address); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("passwords/%s", address)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		b.Logger().Error("Failed to retrieve the account by address", "path", path, "error", err)
		return nil, err
	}
	if entry == nil {
		// could not find the corresponding key for the address
		return nil, nil
	}
	var accountPassword AccountPassword
	_ = entry.DecodeJSON(&accountPassword)
	return &accountPassword, nil
}

func (b *backend) validateAddress(address string) error {
	matched, err := regexp.MatchString("^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{49,50}$", address)
	if !matched || err != nil {
		b.Logger().Error("Failed to retrieve the account, malformatted account address", "address", address, "error", err)
		return fmt.Errorf("Failed to retrieve the account, malformatted account address")
	}

	if _, err = base58.DecodeCheck(address); err != nil {
		b.Logger().Error("Failed to retrieve the account, invalid account address", "address", address, "error", err)
		return fmt.Errorf("Failed to retrieve the account, invalid account address")
	}
	return nil
}

func ZeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}
