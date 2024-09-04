package model

import "github.com/piprate/json-gold/ld"

type CredentialContext map[string]interface{}

type SignatureSuiteOptions struct {
	DocumentLoader ld.DocumentLoader                 // optional custom document loader. If not provided, default will be used
	Contexts       map[string]map[string]interface{} // aditional credential contexts, will be merges in the defaults
}
