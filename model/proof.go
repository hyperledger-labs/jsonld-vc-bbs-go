package model

import (
	"encoding/json"
	"fmt"
	"time"

	c "github.com/hyperledger-labs/jsonld-vc-bbs-go/constants"
)

// CredentialProof The JSON-LD Proof.
type CredentialProof struct {
	Context            []string `json:"@context,omitempty"`
	Type               string   `json:"type"`
	Created            string   `json:"created"`
	ProofPurpose       string   `json:"proofPurpose"`
	VerificationMethod string   `json:"verificationMethod"`
	Nonce              string   `json:"nonce,omitempty"`
	ProofValue         string   `json:"proofValue,omitempty"`
}

// CredentialProofFromMap Convert a map to a proper CredentialProof.
//
//	proof JsonLDProof The proof as map.
//	compact bool If true, compact the returned proof removing the '@context' field.
//
// returns:
//
//	credentialProof *CredentialProof
//	err error
func CredentialProofFromMap(proof JsonLdProof, compact bool) (*CredentialProof, error) {
	now := time.Now().UTC().Format(c.ProofTimestampFormat)

	defaultProof := &CredentialProof{
		Created:      now,
		Type:         c.CredentialProofTypeBbsBlsSig2020,
		ProofPurpose: c.CredentialProofPurpose,
	}

	if val, ok := proof[c.CredentialFieldCreated]; ok {
		defaultProof.Created = val.(string)
	}

	if val, ok := proof[c.CredentialFieldType]; ok {
		defaultProof.Type = val.(string)
	}

	if val, ok := proof[c.CredentialFieldProofPurpose]; ok {
		defaultProof.ProofPurpose = val.(string)
	}

	if !compact {
		// add context only if the proof does not need to be compact
		if val, ok := proof[c.CredentialFieldContext]; ok && !compact {
			defaultProof.Context = val.([]string)
		} else {
			defaultProof.Context = []string{
				c.ContextCredentialV1,
				c.ContextSecurityBbsV1,
			}
		}
	}

	if val, ok := proof[c.CredentialFieldNonce]; ok {
		defaultProof.Nonce = val.(string)
	}

	if val, ok := proof[c.CredentialFieldVerificationMethod]; ok {
		defaultProof.VerificationMethod = val.(string)
	} else {
		return nil, fmt.Errorf("verification method is required")
	}

	if val, ok := proof[c.CredentialFieldProofValue]; ok {
		defaultProof.ProofValue = val.(string)
	}

	return defaultProof, nil
}

// CredentialProofToMap Convert a CredentialProof to a map.
//
//	proof *CredentialProof The proof to convert.
//
// returns:
//
//	proofMap JsonLDProof
//	err error
func CredentialProofToMap(proof *CredentialProof) (JsonLdProof, error) {
	var proofMap JsonLdProof
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(proofBytes, &proofMap)
	if err != nil {
		return nil, err
	}

	return proofMap, nil
}
