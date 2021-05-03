package secrets

// CAInfo represents the detailed information about a CA
// swagger:model
type CAInfo struct {
	// Common name of the CA certificate
	// required: true
	// example: Lamassu-Root-CA1-RSA4096
	CN string `json:"cn"`

	// Algorithm used to create CA key
	// required: true
	// example: RSA
	KeyType string `json:"key_type"`

	// Length used to create CA key
	// required: true
	// example: 4096
	KeyBits int `json:"key_bits"`

	// Organization of the CA certificate
	// required: true
	// example: Lamassu IoT
	O string `json:"o"`

	// Country Name of the CA certificate
	// required: true
	// example: ES
	C string `json:"c"`

	// State of the CA certificate
	// required: true
	// example: Guipuzcoa
	ST string `json:"st"`

	// Locality of the CA certificate
	// required: true
	// example: Arrasate
	L string `json:"l"`
}

// CA represents a registered CA minimum information
// swagger:model
type CA struct {
	// The name of the CA
	// required: true
	// example: Lamassu-Root-CA1-RSA4096
	Name string `json:"ca_name"`
}

// CAs represents a list of CAs with minimum information
// swagger:model
type CAs struct {
	CAs []CA
}

type Secrets interface {
	GetCAs() (CAs, error)
	GetCAInfo(CA string) (CAInfo, error)
	DeleteCA(CA string) error
}
