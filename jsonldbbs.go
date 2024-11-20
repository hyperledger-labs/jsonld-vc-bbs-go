package jsonldbbs

import (
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/internal/core"
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/model"
)

// NewJsonLDBBSSignatureSuite2020 creates new signature suite
// arguments:
//
//	publicKey []byte The public key to attach to the signed JSON-LD document.
//	privateKey []byte nullable The private key to use to sign the JSON-LD document.
//	options *model.SignatureSuiteOptions nullable
//
// returns:
//
//	suite *core.SignatureSuite2020
func NewJsonLDBBSSignatureSuite2020(
	publicKey,
	privateKey []byte,
	options *model.SignatureSuiteOptions,
) *core.SignatureSuite2020 {
	return core.NewSignatureSuite2020(publicKey, privateKey, options)
}

// NewJsonLDBBSSignatureProofSuite2020 creates new signature proof suite
// arguments:
//
//	publicKey []byte The public key to use to derive and/or verify the proof.
//	options *model.SignatureSuiteOptions nullable
//
// returns:
//
//	suite *core.SignatureProofSuite2020
func NewJsonLDBBSSignatureProofSuite2020(
	publicKey []byte,
	options *model.SignatureSuiteOptions,
) *core.SignatureProofSuite2020 {
	return core.NewSignatureProofSuite2020(publicKey, options)
}
