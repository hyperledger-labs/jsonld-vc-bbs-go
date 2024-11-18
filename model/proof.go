package model

import (
	"time"

	c "github.com/hyperledger-labs/jsonld-vc-bbs-go/constants"
)

// JsonLdProof The JSON-LD Proof.
type JsonLdProof = map[string]interface{}

// AddContextToJsonLdProof Add the default context to the JSON-LD proof, if none is provided.
//
//	proof JsonLDProof The proof as map.
func AddContextToJsonLdProof(proof JsonLdProof) {
	// add proof context if it is compacted
	if proof[c.CredentialFieldContext] == nil {
		proof[c.CredentialFieldContext] = []string{
			c.ContextCredentialV1,
			c.ContextSecurityBbsV1,
		}
	}
}

// DeleteContextFromJsonLdProof Delete the '@context' field frmo the JSON-LD Proof.
//
//	proof JsonLDProof The proof as map.
func DeleteContextFromJsonLdProof(proof JsonLdProof) {
	delete(proof, c.CredentialFieldContext)
}

// CreateDefaultJsonLDProof Create a default JSON-LD Proof object.
//
//	verificationMethod string The verification method to embed in the proof.
//	compact bool If true, skip the addition of the '@context' in the proof object.
//
// returns:
//
//	proof JsonLdProof The JSON-LD proof.
func CreateDefaultJsonLDProof(verificationMethod string, compact bool) JsonLdProof {
	defaultProof := JsonLdProof{
		c.CredentialFieldCreated:            time.Now().UTC().Format(c.ProofTimestampFormat),
		c.CredentialFieldVerificationMethod: verificationMethod,
		c.CredentialFieldType:               c.CredentialProofTypeBbsBlsSig2020,
		c.CredentialFieldProofPurpose:       c.CredentialProofPurpose,
	}

	if !compact {
		AddContextToJsonLdProof(defaultProof)
	}

	return defaultProof
}
