package constants

const (
	MulticodecPrefixBls12_381_g1_pub   = 0xea
	MulticodecPrefixBls12_381_g2_pub   = 0xeb
	MulticodecPrefixBls12_381_g1g2_pub = 0xee
)

const (
	CredentialProofPurpose                  = "assertionMethod"
	CredentialProofTypeBbsBlsSig2020        = "BbsBlsSignature2020"
	CredentialProofTypeSecBbsBlsSig2020     = "sec:BbsBlsSignature2020"
	CredentialDerivedProofTypeBbsBlsSig2020 = "BbsBlsSignatureProof2020"
)

const (
	ContextCredentialV1           = "https://www.w3.org/2018/credentials/v1"
	ContextSecurityBbsV1          = "https://w3id.org/security/bbs/v1"
	ContextVCRevocationList2020V1 = "https://w3id.org/vc-revocation-list-2020/v1"
	ContextCitizenshipV1          = "https://w3id.org/citizenship/v1"
	ContextSecurityV2             = "https://w3id.org/security/v2"
)

const ProofTimestampFormat = "2006-01-02T15:04:05Z"
