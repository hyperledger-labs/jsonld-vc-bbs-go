package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	ml "github.com/IBM/mathlib"
	c "github.com/hyperledger-labs/jsonld-vc-bbs-go/constants"
	"github.com/hyperledger-labs/jsonld-vc-bbs-go/model"
	"github.com/hyperledger/aries-bbs-go/bbs"
)

// SignatureProofSuite2020 is initialized with:
//
//	publicKey []byte
//
// Default document loader will has following contexts pre-loaded:
//   - https://www.w3.org/2018/credentials/v1
//   - https://w3id.org/security/bbs/v1
//   - https://w3id.org/citizenship/v1
//   - https://w3id.org/vc-revocation-list-2020/v1
//
// If context is not found, document loader will try to download it from the internet
type SignatureProofSuite2020 struct {
	publicKey                  []byte
	normalizer                 *normalizer
	supportedDerivedProofTypes []string
	documentSignatureSuite     *SignatureSuite2020
	mappedDerivedProofType     string
	curve                      *bbs.BBSG2Pub
}

// NewSignatureProofSuite2020 initializes and returns SignatureProofSuite.
//
//	publicKey []byte
func NewSignatureProofSuite2020(
	publicKey []byte,
	options *model.SignatureSuiteOptions,
) *SignatureProofSuite2020 {
	return &SignatureProofSuite2020{
		publicKey:  publicKey,
		normalizer: NewNormalizer(options),
		supportedDerivedProofTypes: []string{
			c.CredentialProofTypeBbsBlsSig2020,
			c.CredentialProofTypeSecBbsBlsSig2020,
		},
		documentSignatureSuite: NewSignatureSuite2020(publicKey, nil, options),
		mappedDerivedProofType: c.CredentialProofTypeBbsBlsSig2020,
		curve:                  bbs.New(ml.Curves[ml.BLS12_381_BBS]),
	}
}

// DeriveProof Derive a proof for the frame of a signed credential.
//
//	signedCredential model.JsonLdCredential The signed JSON-LD credential.
//	frameDocument model.JsonLDFrame The frame document.
//	nonceBytes []byte The bytes to use for the proof generation.
//
// returns:
//
//	proof model.JsonLdCredential
//	err error
func (s *SignatureProofSuite2020) DeriveProof(signedCredential model.JsonLdCredential, frameDocument model.JsonLdFrame, nonceBytes []byte) (model.JsonLdCredential, error) {
	// 1. Retrieve all the proofs from the credential that can be used to derive our proof
	credWithoutProofs, proofs, err := s.getSupportedProofs(signedCredential)
	if err != nil {
		return nil, err
	}
	if len(proofs) == 0 {
		return nil, fmt.Errorf("There were not any proofs provided that can be used to derive a proof with this suite.")
	}

	// 2. Compute framed cred and derivedProof
	framedCredential, derivedProof, err := s.deriveProof(credWithoutProofs, proofs[0], frameDocument, nonceBytes)
	if err != nil {
		return nil, err
	}

	// 3. Compute additional derivedProofs if necessary
	if len(proofs) > 1 {
		// 3.1.a. If multiple proofs have been found, add them in an array of derived proofs
		derivedProofs := make([]interface{}, len(proofs))
		derivedProofs[0] = derivedProof

		for i, proof := range proofs[1:] {
			_, newDerivedProof, err := s.deriveProof(credWithoutProofs, proof, frameDocument, nonceBytes)
			if err != nil {
				return nil, err
			}
			derivedProofs[i+1] = newDerivedProof
		}
		framedCredential[c.CredentialFieldProof] = derivedProofs
	} else {
		// 3.1.b. No multiple proofs have been found -> add the derived proof generated at step 2.
		framedCredential[c.CredentialFieldProof] = derivedProof
	}

	return framedCredential, nil
}

// VerifyProof Verify a derived proof of a framed credential.
//
//	signedCredential model.JsonLdCredential The framed credential together with the proof.
//
// returns:
//
//	result *model.VerificationResult
func (s *SignatureProofSuite2020) VerifyProof(signedCredential model.JsonLdCredential) *model.VerificationResult {
	signedCredentialCopy := deepCopyMap(signedCredential)
	// 1. Retrieve the proof from the credential and parse it
	proofs, err := s.getDerivedProofs(signedCredentialCopy)
	if err != nil {
		return &model.VerificationResult{
			Success: false,
			Error:   err,
		}
	}
	if len(proofs) == 0 {
		return &model.VerificationResult{
			Success: false,
			Error:   fmt.Errorf("There were not any provided proofs that can be verified with this suite."),
		}
	}

	for _, proof := range proofs {
		proofValueB64, ok := proof[c.CredentialFieldProofValue].(string)
		if !ok {
			return &model.VerificationResult{
				Success: false,
				Error:   fmt.Errorf("Cannot retrieve the proofValue from within the proof."),
			}
		}
		proofValueBytes, err := base64.StdEncoding.DecodeString(proofValueB64)
		if err != nil {
			return &model.VerificationResult{
				Success: false,
				Error:   fmt.Errorf("The proofValue is not in base64: %w", err),
			}
		}

		// 2. Strip off the signature and nonce from the proof in order to recompute the signed statements
		unsignedProof, _, err := s.createVerifyProofData(proof)
		if err != nil {
			return &model.VerificationResult{
				Success: false,
				Error:   err,
			}
		}

		// 3. Retrieve and parse the nonce used to generate the proof
		nonceB64, ok := proof[c.CredentialFieldNonce].(string)
		if !ok {
			return &model.VerificationResult{
				Success: false,
				Error:   fmt.Errorf("Cannot retrieve the nonce from within the proof."),
			}
		}
		nonceBytes, err := base64.StdEncoding.DecodeString(nonceB64)
		if err != nil {
			return &model.VerificationResult{
				Success: false,
				Error:   fmt.Errorf("The nonce is not in base64: %w", err),
			}
		}

		// 4. Recreate the unsigned unsignedCredential
		unsignedCredential := signedCredentialCopy
		delete(signedCredentialCopy, c.CredentialFieldProof)

		// 5. Retrieve the statements to verify
		statementsToVerify, err := s.documentSignatureSuite.prepareDataForSigning(unsignedCredential, unsignedProof)
		if err != nil {
			return &model.VerificationResult{
				Success: false,
				Error:   err,
			}
		}

		// 6. Perform the proof verification
		err = s.curve.VerifyProof(statementsToVerify, proofValueBytes, nonceBytes, s.publicKey)
		if err != nil {
			return &model.VerificationResult{
				Success: false,
				Error:   err,
			}
		}
	}

	return &model.VerificationResult{
		Success: true,
	}
}

// deriveProof Frame a signed JSON-LD credential and generate a verifiable proof.
//
//	credential model.JsonLdCredentialNoProof The unsigned JSON-LD credential.
//	proof model.JsonLDProof The original proof from where derive the proof for the framed credential.
//	frameDocument model.JsonLDFrame The frame document.
//	nonceBytes []byte The bytes to use for the proof generation.
//
// returns:
//
//	framedCredential model.JsonLdCredential
//	derivedProof model.JsonLDProof
//	err error
func (s *SignatureProofSuite2020) deriveProof(
	credential model.JsonLdCredentialNoProof,
	proof model.JsonLdProof,
	frameDocument model.JsonLdFrame,
	nonceBytes []byte,
) (model.JsonLdCredential, model.JsonLdProof, error) {
	// 0. Check that the nonce has been supplied
	if len(nonceBytes) == 0 {
		return nil, nil, fmt.Errorf("Nonce has not been supplied by the verifier.")
	}

	// 1. Retrieve original proof signature
	signature, hasSignature := proof[c.CredentialFieldProofValue]
	if !hasSignature {
		return nil, nil, fmt.Errorf("Cannot derive proof: original proof does not contain proofValue")
	}
	signatureB64, ok := signature.(string)
	if !ok {
		return nil, nil, fmt.Errorf("Signature is not a string")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, nil, fmt.Errorf("The signature is not in base64: %w", err)
	}

	// 2. Normalize the JSON-LD credential
	credentialStatements, err := s.createVerifyDocumentData(credential)
	if err != nil {
		return nil, nil, err
	}

	// 3. Normalize the JSON-LD proof as it would have been signed by the signer
	unsignedProof, proofStatements, err := s.createVerifyProofData(proof)
	if err != nil {
		return nil, nil, err
	}

	// 4. Frame the credential against the frameDocument
	framedCredentialResult, err := s.normalizer.Frame(credential, frameDocument)
	if err != nil {
		return nil, nil, err
	}
	framedCredentialResult[c.CredentialFieldContext] = credential[c.CredentialFieldContext]

	// 5. Normalize the obtained JSON-LD frame
	framedCredentialStatements, err := s.createVerifyDocumentData(framedCredentialResult)
	if err != nil {
		return nil, nil, err
	}

	// 6. Compute the indexes of the statements to disclose
	numberOfProofStatements := len(proofStatements)

	// 6.1. Compute the indexes of the proof -> always disclose the proof statements
	proofIndexesToReveal := make([]int, numberOfProofStatements)
	for i := range proofIndexesToReveal {
		proofIndexesToReveal[i] = i
	}

	// 6.2. Compute the indexes of the statements to disclose within the credential
	credIndexesToReveal := make([]int, 0)
	for _, revealedStatement := range framedCredentialStatements {
		statementIndex := slices.Index(credentialStatements, revealedStatement)
		if statementIndex > -1 {
			credIndexesToReveal = append(credIndexesToReveal, statementIndex+numberOfProofStatements)
		}
	}

	if len(credIndexesToReveal) != len(framedCredentialStatements) {
		return nil, nil, fmt.Errorf("Some statements in the frame document not found in the original proof")
	}

	// 6.3. Merge the indexes to disclose in one array
	indexesToReveal := append(proofIndexesToReveal, credIndexesToReveal...)

	// 7. Compute all the original statements over which the original signature has been performed
	allCredStatements, err := s.documentSignatureSuite.prepareDataForSigning(credential, unsignedProof)
	if err != nil {
		return nil, nil, err
	}

	// 8. Generate the new signature
	outputProof, err := s.curve.DeriveProof(allCredStatements, sigBytes, nonceBytes, s.publicKey, indexesToReveal)
	if err != nil {
		return nil, nil, err
	}

	// 9. Embed the signature in the derivedProof
	derivedProof := model.JsonLdProof{}
	derivedProof[c.CredentialFieldType] = c.CredentialDerivedProofTypeBbsBlsSig2020
	derivedProof[c.CredentialFieldProofPurpose] = c.CredentialProofPurpose
	derivedProof[c.CredentialFieldVerificationMethod] = proof[c.CredentialFieldVerificationMethod]
	derivedProof[c.CredentialFieldNonce] = base64.StdEncoding.EncodeToString(nonceBytes)
	derivedProof[c.CredentialFieldProofValue] = base64.StdEncoding.EncodeToString(outputProof)
	derivedProof[c.CredentialFieldCreated] = proof[c.CredentialFieldCreated]

	return framedCredentialResult, derivedProof, nil
}

// createVerifyDocumentData Normalize an unsigned JSON-LD credential.
//
//	credential model.JsonLdCredentialNoProof The unsigned JSON-LD credential.
//
// returns:
//
//	normalizedCredential []string
//	err error
func (s *SignatureProofSuite2020) createVerifyDocumentData(credential model.JsonLdCredentialNoProof) ([]string, error) {
	credBytes, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}

	return s.normalizer.Normalize(string(credBytes))
}

// createVerifyProofData Normalize the proof of a JSON-LD credential.
//
//	proof model.JsonLDProof The JSON-LD proof to normalize.
//
// returns:
//
//	unsignedProof *model.CredentialProof
//	normalizedProof []string
//	err error
func (s *SignatureProofSuite2020) createVerifyProofData(proof model.JsonLdProof) (model.JsonLdProof, []string, error) {
	unsignedProof := deepCopyMap(proof)

	// add proof context if it is compacted
	model.AddContextToJsonLdProof(unsignedProof)

	delete(unsignedProof, c.CredentialFieldNonce)
	delete(unsignedProof, c.CredentialFieldProofValue)

	proofBytes, err := json.Marshal(unsignedProof)
	if err != nil {
		return nil, nil, err
	}

	proofStatements, err := s.normalizer.Normalize(string(proofBytes))
	if err != nil {
		return nil, nil, err
	}

	return unsignedProof, proofStatements, nil
}

// getDerivedProofs Retrieve the derived proofs from a framed JSON-LD credential.
//
//	signedCredential model.JsonLdCredential The framed JSON-LD credential.
//
// returns:
//
//	derivedProof model.JsonLDProof
//	err error
func (s *SignatureProofSuite2020) getDerivedProofs(framedCredential model.JsonLdCredential) ([]model.JsonLdProof, error) {
	derivedProofs, _ := s.getProofs(framedCredential)

	for _, proof := range derivedProofs {
		proofType, ok := proof[c.CredentialFieldType].(string)
		if !ok {
			return nil, fmt.Errorf("Cannot retrieve the proof type.")
		}
		if proofType != c.CredentialDerivedProofTypeBbsBlsSig2020 {
			return nil, fmt.Errorf("Expected %s proof type, got %s.", c.CredentialDerivedProofTypeBbsBlsSig2020, proofType)
		}

		// map derived proof type to the original one for later verification
		proof[c.CredentialFieldType] = s.mappedDerivedProofType
	}

	return derivedProofs, nil
}

// getSupportedProofs Retrieve all the proofs within the JSON-LD credential that can be used
// by this suite to derive a proof.
//
//	signedCredential model.JsonLdCredential The JSON-LD framed credential.
//
// returns:
//
//	unsignedCredential model.JsonLdCredentialNoProof
//	proofs []model.JsonLDProof
//	err error
func (s *SignatureProofSuite2020) getSupportedProofs(signedCredential model.JsonLdCredential) (model.JsonLdCredentialNoProof, []model.JsonLdProof, error) {
	// 1. Expand the JSON-LD credential against the proof context
	expandedCredential, err := s.normalizer.Compact(signedCredential, c.ContextSecurityV2)
	if err != nil {
		return nil, nil, err
	}

	// 2. Extract all the proofs within the expanded credential
	credProofsArray, err := s.getProofs(expandedCredential)
	if err != nil {
		return nil, nil, err
	}

	// 3. Filter out all proofs not supported by the current suite
	proofs := make([]model.JsonLdProof, 0)
	for _, proof := range credProofsArray {
		proofType := proof[c.CredentialFieldType].(string)

		if slices.Contains(s.supportedDerivedProofTypes, proofType) {
			context := make([]string, 0)
			context = append(context, c.ContextSecurityV2)
			proof[c.CredentialFieldContext] = context
			proofs = append(proofs, proof)
		}
	}

	// 4. Re-compact the credential without the proof
	delete(expandedCredential, c.CredentialFieldProof)
	compactedDoc, err := s.normalizer.Compact(expandedCredential, signedCredential[c.CredentialFieldContext])
	if err != nil {
		return nil, nil, err
	}

	return compactedDoc, proofs, nil
}

func (s *SignatureProofSuite2020) getProofs(signedCredential model.JsonLdCredential) ([]model.JsonLdProof, error) {
	proofObj, ok := signedCredential[c.CredentialFieldProof]
	if !ok {
		return nil, fmt.Errorf("The credential is not signed: no proof has been found.")
	}

	proofArray, isArray := proofObj.([]interface{})
	if !isArray {
		proof, ok := proofObj.(model.JsonLdProof)
		if !ok {
			return nil, fmt.Errorf("The proof is not correctly formatted.")
		}

		proofArray = append(proofArray, proof)
	}

	proofs := make([]model.JsonLdProof, len(proofArray))
	for i, proof1 := range proofArray {
		proof, ok := proof1.(model.JsonLdProof)
		if !ok {
			return nil, fmt.Errorf("The proof is not correctly formatted.")
		}
		proofs[i] = proof
	}

	return proofs, nil
}
