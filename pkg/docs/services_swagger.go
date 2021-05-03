package docs

// Health swagger:route GET /v1/health lamassu-ca health
//
// Gets service health.
//
// Produces:
//	- application/json
// Responses:
//	default: healthResponse
//	200: healthResponse

// GetCAs swagger:route GET /cas lamassu-ca getCAs
//
// Gets CAs information from Vault.
//
// Produces:
//	- application/json
// Responses:
//	default: getCAsResponse
//	200: getCAsResponse
//	500:

// GetCAInfo swagger:route GET /cas/{ca} lamassu-ca getCAInfo
//
// Gets detailed CA information from Vault.
//
// Produces:
//	- application/json
// Responses:
//	default: getCAInfoResponse
//	200: getCAInfoResponse
//	400:
//	500:

// DeleteCA swagger:route DELETE /cas/{ca} lamassu-ca deleteCA
//
// Deletes or revokes CA from Vault.
//
// Produces:
//	- application/json
// Responses:
//	default: deleteCAResponse
//	200: deleteCAResponse
//	500:
