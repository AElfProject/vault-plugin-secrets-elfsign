package base58

import (
	"crypto/sha256"
	"errors"
)

// ErrChecksum indicates that the checksum of a check-encoded string does not verify against
// the checksum.
var ErrChecksum = errors.New("checksum error")

// ErrInvalidFormat indicates that the check-encoded string has an invalid format.
var ErrInvalidFormat = errors.New("invalid format: checksum bytes missing")

// checksum: first four bytes of sha256^2
func checksum(input []byte) (cksum [4]byte) {
	h := sha256.Sum256(input)
	h2 := sha256.Sum256(h[:])
	copy(cksum[:], h2[:4])
	return
}

// EncodeCheck appends a four byte checksum.
func EncodeCheck(input []byte) string {
	b := make([]byte, 0, 1+len(input)+4)
	b = append(b, input...)
	cksum := checksum(b)
	b = append(b, cksum[:]...)
	return Encode(b)
}

// DecodeCheck decodes a string that was encoded with EncodeCheck and verifies the checksum.
func DecodeCheck(input string) (result []byte, err error) {
	decoded := Decode(input)
	if len(decoded) < 4 {
		return nil, ErrInvalidFormat
	}
	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])
	payload := decoded[:len(decoded)-4]
	if checksum(payload) != cksum {
		return nil, ErrChecksum
	}
	result = payload
	return
}
