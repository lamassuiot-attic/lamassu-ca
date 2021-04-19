package secrets

type CAInfo struct {
	CN      string `json:"cn"`
	KeyType string `json:"key_type"`
	KeyBits int    `json:"key_bits"`
	O       string `json:"o"`
	C       string `json:"c"`
	ST      string `json:"st"`
	L       string `json:"l"`
}

type CA struct {
	Name string `json:"ca_name"`
}

type CAs struct {
	CAs []CA
}

type Secrets interface {
	GetCAs() (CAs, error)
	GetCAInfo(CA string) (CAInfo, error)
	DeleteCA(CA string) error
}
