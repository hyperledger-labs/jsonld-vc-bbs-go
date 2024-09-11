package core

import (
	"encoding/binary"
	"fmt"

	"github.com/hyperledger-labs/jsonld-vc-bbs-go/constants"
	multibase "github.com/multiformats/go-multibase"
)

// A KeyEncoder struct encapsulates operations with bls public key
// Supported curve is BLS12_381
type KeyEncoder struct{}

// CreateDidKey Create a did:key from the bytes of a BLS public key.
//
//	blsPublicKey []byte
//
// returns:
//
//	didKey string example: "did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e"
//	err error
func (e *KeyEncoder) CreateDidKey(blsPublicKey []byte) (string, error) {
	key, err := e.multibaseEncode(blsPublicKey)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("did:key:%s", key), nil
}

// CreateDidKeyVerificationMethod Create a did:key to use for a specific verification method.
//
//	blsPublicKey []byte
//
// returns:
//
//	verificationMethod string example: "did:key:z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e#z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e"
//	err error
func (e *KeyEncoder) CreateDidKeyVerificationMethod(blsPublicKey []byte) (string, error) {
	key, err := e.multibaseEncode(blsPublicKey)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("did:key:%s#%s", key, key), nil
}

// multibaseEncode Encode a BLS public key in multibase.
//
//	blsPublicKey []byte The BLS public key bytes.
//
// returns:
//
//	multibaseKey string example: "z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e#z6MknntgQWCT8Zs5vpQEVoV2HvsfdYfe7b1LTnM9Lty6fD4e"
//	err error
func (e *KeyEncoder) multibaseEncode(blsPublicKey []byte) (string, error) {
	// public key must be prefixed with the multicodec prefix encoded in Varint
	encodedUvarintBuffer := make([]byte, 2)
	binary.PutUvarint(encodedUvarintBuffer, constants.MulticodecPrefixBls12_381_g2_pub)

	return multibase.Encode(multibase.Base58BTC, append(encodedUvarintBuffer, blsPublicKey...))
}
