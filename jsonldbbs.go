package jsonldbbs

import (
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/internal/core"
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/model"
)

// NewJsonLDBBSSignatureSuite2020 creates new signature suite
// arguments:
//
//	publicKey []byte
//	privateKey []byte nullable
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
