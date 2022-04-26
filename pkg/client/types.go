package lamassuca

type Cert struct {
	// The status of the CA
	// required: true
	// example: issued | expired
	Status string `json:"status,omitempty"`

	// The serial number of the CA
	// required: true
	// example: 7e:36:13:a5:31:9f:4a:76:10:64:2e:9b:0a:11:07:b7:e6:3e:cf:94
	SerialNumber string `json:"serial_number,omitempty"`

	// The name/alias of the CA
	// required: true
	// example: Lamassu-CA
	CAName string `json:"name,omitempty"`

	KeyMetadata KeyInfo `json:"key_metadata"`

	Subject Subject `json:"subject"`

	CertContent CertContent `json:"certificate"`

	// Expiration period of the new emmited CA
	// required: true
	// example: 262800h
	CaTTL int `json:"ca_ttl,omitempty"`

	EnrollerTTL int `json:"enroller_ttl,omitempty"`

	ValidFrom           string `json:"valid_from"`
	ValidTo             string `json:"valid_to"`
	RevocationTimestamp int64  `json:"revocation_timestamp,omitempty"`
}

type CAImport struct {
	PEMBundle string `json:"pem_bundle"`
	TTL       int    `json:"ttl"`
}
type CertContent struct {
	CerificateBase64 string `json:"pem_base64, omitempty"`
	PublicKeyBase64  string `json:"public_key_base64"`
}

type KeyInfo struct {
	// Algorithm used to create CA key
	// required: true
	// example: RSA
	KeyType string `json:"type"`

	// Length used to create CA key
	// required: true
	// example: 4096
	KeyBits int `json:"bits"`

	// Strength of the key used to the create CA
	// required: true
	// example: low
	KeyStrength string `json:"strength"`
}

type Subject struct {
	// Common name of the CA certificate
	// required: true
	// example: Lamassu-Root-CA1-RSA4096
	CN string `json:"common_name"`

	// Organization of the CA certificate
	// required: true
	// example: Lamassu IoT
	O string `json:"organization"`

	// Organization Unit of the CA certificate
	// required: true
	// example: Lamassu IoT department 1
	OU string `json:"organization_unit"`

	// Country Name of the CA certificate
	// required: true
	// example: ES
	C string `json:"country"`

	// State of the CA certificate
	// required: true
	// example: Guipuzcoa
	ST string `json:"state"`

	// Locality of the CA certificate
	// required: true
	// example: Arrasate
	L string `json:"locality"`
}

// CAs represents a list of CAs with minimum information
// swagger:model
type Certs struct {
	Certs []Cert `json:"certs"`
}
type Certificate struct {
	Cert string `json:"crt"`
}
