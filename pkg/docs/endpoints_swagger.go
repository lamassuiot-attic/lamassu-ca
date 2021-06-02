package docs

import "github.com/lamassuiot/lamassu-ca/pkg/api"

// A HealthResponse returns if the service is healthy
// swagger:response healthResponse
type healthResponseWrapper struct {
	// The health response
	// in: body
	Body api.HealthResponse
}

// A GetCAsResponse returns a list of CAs
// swagger:response getCAsResponse
type getCAsResponseWrapper struct {
	// The CAs list
	// in: body
	Body api.GetCAsResponse
}
