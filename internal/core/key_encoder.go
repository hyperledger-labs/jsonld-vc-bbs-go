package core

import (
	"encoding/binary"
	"fmt"

	"github.com/hyperledger-labs/jsonld-vc-bbs-go/constants"
	multibase "github.com/multiformats/go-multibase"
)

// A KeyEncoder struct encapsulates operations with bls public key
// Supported curve is BLS 12_381
type KeyEncoder struct {
}

// CreateDidKey
//
// arguments:
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

// CreateDidKeyVerificationMethod
//
// arguments:
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

func (e *KeyEncoder) multibaseEncode(blsPublicKey []byte) (string, error) {
	// public key must be prefixed with the multicodec prefix encoded in Varint
	encodedUvarintBuffer := make([]byte, 2)
	binary.PutUvarint(encodedUvarintBuffer, constants.MulticodecPrefixBls12_381_g2_pub)

	return multibase.Encode(multibase.Base58BTC, append(encodedUvarintBuffer, blsPublicKey...))
}
