package model

import (
	"fmt"
	"time"

	c "github.com/hyperledger-labs/jsonld-vc-bbs-go/constants"
)

type CredentialProof struct {
	Context            []string `json:"@context,omitempty"`
	Type               string   `json:"type"`
	Created            string   `json:"created"`
	ProofPurpose       string   `json:"proofPurpose"`
	VerificationMethod string   `json:"verificationMethod"`
	ProofValue         string   `json:"proofValue,omitempty"`
}

func CredentialProofFromMap(proof map[string]interface{}) (*CredentialProof, error) {
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	defaultProof := &CredentialProof{
		Created:      now,
		Type:         c.CredentialProofTypeBbsBlsSig2020,
		ProofPurpose: c.CredentialProofPurpose,
		Context: []string{
			c.ContextLinkCredentialV1,
			c.ContextLinkSecurityBBSV1,
		},
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

	if val, ok := proof[c.CredentialFieldContext]; ok {
		defaultProof.Context = val.([]string)
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
