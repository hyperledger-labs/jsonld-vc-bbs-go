package model

// VerificationResult Wrapper to contain the error in case the verification failed.
type VerificationResult struct {
	Success bool
	Error   error
}
