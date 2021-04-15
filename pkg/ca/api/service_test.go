package api

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/lamassuiot/enroller/pkg/ca/mocks"
	"github.com/lamassuiot/enroller/pkg/ca/secrets"
)

type serviceSetUp struct {
	secrets secrets.Secrets
}

func TestGetCAs(t *testing.T) {
	stu, ln := setup(t)
	srv := NewCAService(stu.secrets)
	ctx := context.Background()

	defer ln.Close()
	cas, err := srv.GetCAs(ctx)
	if err != nil {
		t.Errorf("CA API returned error: %s", err)
	}
	if len(cas.CAs) <= 0 {
		t.Errorf("Not CA certificates returned from CA API")
	}
	if len(cas.CAs) != 1 {
		t.Errorf("CA API expected to return one certificate, but %d certificates were returned", len(cas.CAs))
	}
}

func TestGetCAInfo(t *testing.T) {
	stu, ln := setup(t)
	srv := NewCAService(stu.secrets)
	ctx := context.Background()

	defer ln.Close()
	testCases := []struct {
		name   string
		caname string
		cainfo secrets.CAInfo
		ret    error
	}{
		{"Get CA Info does not exist", "doesNotExist", secrets.CAInfo{}, errInvalidCA},
		{"Get CA Info exists", "Lamassu-Root-CA1-RSA4096", secrets.CAInfo{
			C:       "ES",
			CN:      "LKS Next Root CA 1",
			KeyBits: 4096,
			KeyType: "RSA",
			L:       "Arrasate",
			O:       "LKS Next S. Coop",
			ST:      "Gipuzkoa",
		}, nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			cainfo, err := srv.GetCAInfo(ctx, tc.caname)
			if tc.ret != err {
				t.Errorf("Got result is %s; want %s", err, tc.ret)
			}
			if tc.cainfo != cainfo {
				t.Errorf("Got result is %v; want %v", cainfo, tc.cainfo)
			}
		})
	}
}

func TestDeleteCA(t *testing.T) {

}

func setup(t *testing.T) (*serviceSetUp, net.Listener) {
	t.Helper()

	vaultSecrets, ln, err := mocks.NewVaultSecretsMock(t)
	if err != nil {
		t.Fatal("Unable to mock Vault server")
	}
	return &serviceSetUp{vaultSecrets}, ln
}
