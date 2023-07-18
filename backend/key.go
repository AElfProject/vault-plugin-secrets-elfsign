package backend

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/AElfProject/vault-plugin-secrets-elfsign/base58"
	keystore "github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

type encryptedKeyJSONV3 struct {
	Address string              `json:"address"`
	Crypto  keystore.CryptoJSON `json:"crypto"`
	Id      string              `json:"id"`
	Version int                 `json:"version"`
}

func genRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func newKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) *keystore.Key {
	id, err := uuid.NewRandom()
	if err != nil {
		panic(fmt.Sprintf("Could not create random uuid: %v", err))
	}
	key := &keystore.Key{
		Id:         id,
		PrivateKey: privateKeyECDSA,
	}
	return key
}

func ToKeyStore(privateKeyECDSA *ecdsa.PrivateKey) (*encryptedKeyJSONV3, *string, error) {
	rBytes, err := genRandomBytes(20)
	if err != nil {
		return nil, nil, err
	}
	auth := base58.Encode(rBytes)
	key := newKeyFromECDSA(privateKeyECDSA)
	ksBytes, err := keystore.EncryptKey(key, auth, keystore.LightScryptN, keystore.LightScryptP)
	if err != nil {
		return nil, nil, err
	}
	address := getAelfAddress(privateKeyECDSA)
	ks := &encryptedKeyJSONV3{}
	err = json.Unmarshal(ksBytes, ks)
	if err != nil {
		return nil, nil, err
	}
	ks.Address = address
	return ks, &auth, nil
}

func getAelfAddress(privateKeyECDSA *ecdsa.PrivateKey) string {
	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	sum1 := sha256.Sum256(publicKeyBytes)
	sum2 := sha256.Sum256(sum1[:])
	return base58.EncodeCheck(sum2[:])
}
