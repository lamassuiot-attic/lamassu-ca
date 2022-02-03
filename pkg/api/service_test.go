package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"
	"testing"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassu-ca/pkg/mocks"
	"github.com/lamassuiot/lamassu-ca/pkg/secrets"
	"github.com/lamassuiot/lamassu-ca/pkg/secrets/vault"
)

type serviceSetUp struct {
	secrets secrets.Secrets
}

func TestHealth(t *testing.T) {
	srv, ctx := setup(t)
	type testCasesHealth struct {
		name string
		ret  bool
	}
	cases := []testCasesHealth{
		{"Correct", true},
	}
	for _, tc := range cases {

		out := srv.Health(ctx)
		if tc.ret != out {
			t.Errorf("Expected '%s', but got '%s'", strconv.FormatBool(tc.ret), strconv.FormatBool(out))
		}

	}
}

func TestGetSecretProviderName(t *testing.T) {
	srv, ctx := setup(t)

	testCases := []struct {
		name string
		ret  string
	}{
		{"Correct", "Hashicorp_Vault"},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			out := srv.GetSecretProviderName(ctx)
			if tc.ret != out {
				t.Errorf("Secret Provider Name error")
			}
		})
	}
}

func TestCreateCA(t *testing.T) {
	srv, ctx := setup(t)

	caNameC := "FUYF"
	cert := testCA(caNameC)
	caType, _ := secrets.ParseCAType("pki")

	testCases := []struct {
		name    string
		newCert secrets.Cert
		ret     secrets.Cert
		err     error
	}{
		{"Correct CA", cert, cert, nil},
		{"Create empty", secrets.Cert{}, secrets.Cert{}, ErrEmptyCA},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			_, err := srv.CreateCA(ctx, caType, tc.newCert.Name, tc.newCert)
			if tc.ret != tc.newCert {
				t.Errorf("Got result is different of created CA")
			}
			if err != nil {
				if err.Error() != tc.err.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.err)
				}
			}
			if err == nil {
				err = srv.DeleteCA(ctx, caType, tc.newCert.Name)
				if err != nil {
					t.Fatal("Could not delete CA from DB")
				}
			}
		})
	}
}

func TestImportCA(t *testing.T) {
	srv, ctx := setup(t)

	caType, _ := secrets.ParseCAType("pki")
	caImportC := testCAImport()

	testCases := []struct {
		name   string
		caName string
		cert   secrets.CAImport
		ret    error
	}{
		{"Correct CA", "testImport", caImportC, nil},
		{"Incorrect CA", "testImport", caImportC, ErrImportCA},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			err := srv.ImportCA(ctx, caType, tc.caName, tc.cert)
			data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVUV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURDaFUxRFROckI0a2JTaVpjQjBMaHhUQ2dPYXlQUUU0VzkKT2N1MFBpczBybUliZnM2T2pERk5qcUY5dlhOcFlUSGhtL3FaTVZTWEZYZjM4VDBJS3NmU2lCYm5aa0pYWWc0NgptY2tLY1VkQ0VsUy8wK3RYaDh6Slo3QXNsV0Z2eXFLek5nUVJCcnhJQ0RVOTdVWXJ6eWk3ajVOSUJ2OHJvRld4CjVJOUNXUEpEQ00vRUFHMHVldjZQNVQzN2dKUzlFcnZXeERmWDVJL3hxRnZEQnpsV0VqbytFZ1piM3daSEt5d3QKMUVaVHBET1NKY29VeXZnWmFwUFF6U2JDZVdUL3ZlRW8rem5pUlk5SThFRlJhNm9DWDNCbVc4Snh2V2FSOVd3YQpnVUZ4cFM5OHdJN0JwSVJUeFgwdk9oMXZlUlBjWmRsVmFMZlJQb1BuV1BkdHAwckFDdXB6QWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUllbTV5YnpVR1VvSk9yUjc1bW5COGZNUmVBWi9NalRVamYwem0xQjQKeGo4U1FMYTI2djU2ZkxOYkZ6NTlaaDlJa0J2U1AyNWNRTm5JU1lZT3RxejZLakJzcEVVQnNKaFVKcTNRNXpybgo3WVVoZnN2NWIzN0h2Y3h6akpvWW05NlZiU2FwQk5RWStGbjJ3R3NhZ1Zucktoalk0REdMM0lKQmlicmJvcEg2ClJwaFJRMWwyeXcwbUEybG9jK0hEZ1VwVTR4bXRpangvbHZmdHkzYVdwelBmV3pOWFRVYkEwNTFGY3hEQWh0SlkKbEd5WUxKSk1XQ08rL3NlUkxLSWFrZTFNeFR5Nzd0WVJ3MUNkVkJWWWFIbU8xM2k3ek8zYWVxdzloaGNHcWhyUQpXSWlYQ2lRdm9GN25oSmRvOEdmbkV5L1hKWk54LzQzbFVxUFcrekNhaWlsa2h3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t")
			block, _ := pem.Decode([]byte(data))
			csr, _ := x509.ParseCertificateRequest(block.Bytes)

			srv.SignCertificate(ctx, caType, tc.caName, *csr)

			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}

		})
	}
}

func TestGetCAs(t *testing.T) {
	srv, ctx := setup(t)

	caType, _ := secrets.ParseCAType("pki")
	var CAs secrets.Certs
	var caList []secrets.Cert
	ca, _ := srv.CreateCA(ctx, caType, "testMock", testCA("testMock"))
	caList = append(caList, ca)
	CAs = secrets.Certs{Certs: caList}

	var CAEmptys secrets.Certs

	testCases := []struct {
		name string
		res  secrets.Certs
		ret  error
	}{
		{"Incorrect", CAEmptys, ErrGetCAs},
		{"Correct", CAs, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			cas, err := srv.GetCAs(ctx, caType)
			if err != nil {
				if tc.ret != err {
					t.Errorf("CA API returned error: %s", err)
				}
				if len(tc.res.Certs) != len(cas.Certs) {
					t.Errorf("CA has not the same number of certs than expected")
				}
				if len(tc.res.Certs) > 0 {
					for i := 0; i < len(tc.res.Certs); i++ {
						if tc.res.Certs[i] != cas.Certs[i] {
							t.Errorf("CA has not the same certs than expected")
						}
					}
				}
			}
		})
	}
}

func TestGetIssuedCerts(t *testing.T) {
	srv, ctx := setup(t)

	caType, _ := secrets.ParseCAType("pki")
	certReq := testCA("testDCMock")
	newCA, _ := srv.CreateCA(ctx, caType, "testDCMock", certReq)

	data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVUV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURDaFUxRFROckI0a2JTaVpjQjBMaHhUQ2dPYXlQUUU0VzkKT2N1MFBpczBybUliZnM2T2pERk5qcUY5dlhOcFlUSGhtL3FaTVZTWEZYZjM4VDBJS3NmU2lCYm5aa0pYWWc0NgptY2tLY1VkQ0VsUy8wK3RYaDh6Slo3QXNsV0Z2eXFLek5nUVJCcnhJQ0RVOTdVWXJ6eWk3ajVOSUJ2OHJvRld4CjVJOUNXUEpEQ00vRUFHMHVldjZQNVQzN2dKUzlFcnZXeERmWDVJL3hxRnZEQnpsV0VqbytFZ1piM3daSEt5d3QKMUVaVHBET1NKY29VeXZnWmFwUFF6U2JDZVdUL3ZlRW8rem5pUlk5SThFRlJhNm9DWDNCbVc4Snh2V2FSOVd3YQpnVUZ4cFM5OHdJN0JwSVJUeFgwdk9oMXZlUlBjWmRsVmFMZlJQb1BuV1BkdHAwckFDdXB6QWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUllbTV5YnpVR1VvSk9yUjc1bW5COGZNUmVBWi9NalRVamYwem0xQjQKeGo4U1FMYTI2djU2ZkxOYkZ6NTlaaDlJa0J2U1AyNWNRTm5JU1lZT3RxejZLakJzcEVVQnNKaFVKcTNRNXpybgo3WVVoZnN2NWIzN0h2Y3h6akpvWW05NlZiU2FwQk5RWStGbjJ3R3NhZ1Zucktoalk0REdMM0lKQmlicmJvcEg2ClJwaFJRMWwyeXcwbUEybG9jK0hEZ1VwVTR4bXRpangvbHZmdHkzYVdwelBmV3pOWFRVYkEwNTFGY3hEQWh0SlkKbEd5WUxKSk1XQ08rL3NlUkxLSWFrZTFNeFR5Nzd0WVJ3MUNkVkJWWWFIbU8xM2k3ek8zYWVxdzloaGNHcWhyUQpXSWlYQ2lRdm9GN25oSmRvOEdmbkV5L1hKWk54LzQzbFVxUFcrekNhaWlsa2h3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t")
	block, _ := pem.Decode([]byte(data))
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	srv.SignCertificate(ctx, caType, newCA.Name, *csr)
	var CAs secrets.Certs
	var caList []secrets.Cert
	caList = append(caList, newCA)
	CAs = secrets.Certs{Certs: caList}

	var CAEmptys secrets.Certs

	testCases := []struct {
		name string
		res  secrets.Certs
		ret  error
	}{
		{"Incorrect", CAEmptys, ErrGetCAs},
		{"Correct", CAs, nil},
	}
	for _, tc := range testCases {

		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			cas, err := srv.GetIssuedCerts(ctx, caType, newCA.Name)
			if err != nil {
				if tc.ret != err {
					t.Errorf("CA API returned error: %s", err)
				}
				if len(tc.res.Certs) != len(cas.Certs) {
					t.Errorf("CA has not the same number of certs than expected")
				}
				if len(tc.res.Certs) > 0 {
					for i := 0; i < len(tc.res.Certs); i++ {
						if tc.res.Certs[i] != cas.Certs[i] {
							t.Errorf("CA has not the same certs than expected")
						}

					}
				}
			}
		})
	}
}

func TestDeleteCA(t *testing.T) {
	srv, ctx := setup(t)

	caType, err := secrets.ParseCAType("pki")
	caNameC := "testDeleteCA"
	newCA, err := srv.CreateCA(ctx, caType, caNameC, testCA(caNameC))

	data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVUV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURDaFUxRFROckI0a2JTaVpjQjBMaHhUQ2dPYXlQUUU0VzkKT2N1MFBpczBybUliZnM2T2pERk5qcUY5dlhOcFlUSGhtL3FaTVZTWEZYZjM4VDBJS3NmU2lCYm5aa0pYWWc0NgptY2tLY1VkQ0VsUy8wK3RYaDh6Slo3QXNsV0Z2eXFLek5nUVJCcnhJQ0RVOTdVWXJ6eWk3ajVOSUJ2OHJvRld4CjVJOUNXUEpEQ00vRUFHMHVldjZQNVQzN2dKUzlFcnZXeERmWDVJL3hxRnZEQnpsV0VqbytFZ1piM3daSEt5d3QKMUVaVHBET1NKY29VeXZnWmFwUFF6U2JDZVdUL3ZlRW8rem5pUlk5SThFRlJhNm9DWDNCbVc4Snh2V2FSOVd3YQpnVUZ4cFM5OHdJN0JwSVJUeFgwdk9oMXZlUlBjWmRsVmFMZlJQb1BuV1BkdHAwckFDdXB6QWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUllbTV5YnpVR1VvSk9yUjc1bW5COGZNUmVBWi9NalRVamYwem0xQjQKeGo4U1FMYTI2djU2ZkxOYkZ6NTlaaDlJa0J2U1AyNWNRTm5JU1lZT3RxejZLakJzcEVVQnNKaFVKcTNRNXpybgo3WVVoZnN2NWIzN0h2Y3h6akpvWW05NlZiU2FwQk5RWStGbjJ3R3NhZ1Zucktoalk0REdMM0lKQmlicmJvcEg2ClJwaFJRMWwyeXcwbUEybG9jK0hEZ1VwVTR4bXRpangvbHZmdHkzYVdwelBmV3pOWFRVYkEwNTFGY3hEQWh0SlkKbEd5WUxKSk1XQ08rL3NlUkxLSWFrZTFNeFR5Nzd0WVJ3MUNkVkJWWWFIbU8xM2k3ek8zYWVxdzloaGNHcWhyUQpXSWlYQ2lRdm9GN25oSmRvOEdmbkV5L1hKWk54LzQzbFVxUFcrekNhaWlsa2h3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t")
	block, _ := pem.Decode([]byte(data))
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	srv.SignCertificate(ctx, caType, "testDeleteCA", *csr)

	if err != nil {
		t.Fatal("Could not insert CA in DB")
	}

	testCases := []struct {
		name string
		cert secrets.Cert
		ret  error
	}{
		{"Delete not existing CA", testCA("notExists"), ErrDeleteCA},
		{"Delete CA ", newCA, nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {

			err = srv.DeleteCA(ctx, caType, tc.cert.Name)
			if err != nil {
				if err.Error() != tc.ret.Error() {
					t.Errorf("Got result is %s; want %s", err, tc.ret)
				}
			}
		})
	}
	if err != nil {
		t.Fatal("Could not delete CA from file system")
	}
}

func TestGetCert(t *testing.T) {
	srv, ctx := setup(t)

	caType, _ := secrets.ParseCAType("pki")
	caName := "testMockGetCert"
	certReq := testCA(caName)

	newCert, _ := srv.CreateCA(ctx, caType, caName, certReq)

	testCases := []struct {
		name string
		cert secrets.Cert
		ret  secrets.Cert
	}{
		{"Cert exists", testCA(caName), newCert},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			ret, _ := srv.GetCert(ctx, caType, tc.cert.Name, newCert.SerialNumber)
			if ret != tc.ret {
				t.Errorf("Got result is not expected one")
			}
		})
	}
}

func TestSignCertificate(t *testing.T) {
	srv, ctx := setup(t)

	caType, _ := secrets.ParseCAType("pki")
	caName := "testMockGetCert"
	certReq := testCA(caName)

	newCA, _ := srv.CreateCA(ctx, caType, "testDCMock", certReq)
	input := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVUV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURDaFUxRFROckI0a2JTaVpjQjBMaHhUQ2dPYXlQUUU0VzkKT2N1MFBpczBybUliZnM2T2pERk5qcUY5dlhOcFlUSGhtL3FaTVZTWEZYZjM4VDBJS3NmU2lCYm5aa0pYWWc0NgptY2tLY1VkQ0VsUy8wK3RYaDh6Slo3QXNsV0Z2eXFLek5nUVJCcnhJQ0RVOTdVWXJ6eWk3ajVOSUJ2OHJvRld4CjVJOUNXUEpEQ00vRUFHMHVldjZQNVQzN2dKUzlFcnZXeERmWDVJL3hxRnZEQnpsV0VqbytFZ1piM3daSEt5d3QKMUVaVHBET1NKY29VeXZnWmFwUFF6U2JDZVdUL3ZlRW8rem5pUlk5SThFRlJhNm9DWDNCbVc4Snh2V2FSOVd3YQpnVUZ4cFM5OHdJN0JwSVJUeFgwdk9oMXZlUlBjWmRsVmFMZlJQb1BuV1BkdHAwckFDdXB6QWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUllbTV5YnpVR1VvSk9yUjc1bW5COGZNUmVBWi9NalRVamYwem0xQjQKeGo4U1FMYTI2djU2ZkxOYkZ6NTlaaDlJa0J2U1AyNWNRTm5JU1lZT3RxejZLakJzcEVVQnNKaFVKcTNRNXpybgo3WVVoZnN2NWIzN0h2Y3h6akpvWW05NlZiU2FwQk5RWStGbjJ3R3NhZ1Zucktoalk0REdMM0lKQmlicmJvcEg2ClJwaFJRMWwyeXcwbUEybG9jK0hEZ1VwVTR4bXRpangvbHZmdHkzYVdwelBmV3pOWFRVYkEwNTFGY3hEQWh0SlkKbEd5WUxKSk1XQ08rL3NlUkxLSWFrZTFNeFR5Nzd0WVJ3MUNkVkJWWWFIbU8xM2k3ek8zYWVxdzloaGNHcWhyUQpXSWlYQ2lRdm9GN25oSmRvOEdmbkV5L1hKWk54LzQzbFVxUFcrekNhaWlsa2h3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t"
	data, _ := base64.StdEncoding.DecodeString(input)
	block, _ := pem.Decode([]byte(data))
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	testCases := []struct {
		name string
		in   *x509.CertificateRequest
	}{
		{"Correct", csr},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			ret, err := srv.SignCertificate(ctx, caType, newCA.Name, *csr)
			if len(ret) <= 0 {
				t.Errorf("Empty signed certificate")
			}
			if err != nil {
				t.Errorf("Error signing certificate")
			}

		})
	}
}
func TestDeleteCert(t *testing.T) {
	srv, ctx := setup(t)

	caType, _ := secrets.ParseCAType("pki")
	certReq := testCA("testDCMockc")
	newCA, err := srv.CreateCA(ctx, caType, "testDCMockc", certReq)
	newCAI, err := srv.CreateCA(ctx, caType, "testDCMockIn", certReq)
	err = srv.DeleteCert(ctx, caType, "testDCMockIn", newCAI.SerialNumber)

	data, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2pqQ0NBWFlDQVFBd1NURUxNQWtHQTFVRUJoTUNSVk14Q2pBSUJnTlZCQWdNQVVFeENqQUlCZ05WQkFjTQpBVUV4Q2pBSUJnTlZCQW9NQVVFeENqQUlCZ05WQkFzTUFVRXhDakFJQmdOVkJBTU1BVUV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURDaFUxRFROckI0a2JTaVpjQjBMaHhUQ2dPYXlQUUU0VzkKT2N1MFBpczBybUliZnM2T2pERk5qcUY5dlhOcFlUSGhtL3FaTVZTWEZYZjM4VDBJS3NmU2lCYm5aa0pYWWc0NgptY2tLY1VkQ0VsUy8wK3RYaDh6Slo3QXNsV0Z2eXFLek5nUVJCcnhJQ0RVOTdVWXJ6eWk3ajVOSUJ2OHJvRld4CjVJOUNXUEpEQ00vRUFHMHVldjZQNVQzN2dKUzlFcnZXeERmWDVJL3hxRnZEQnpsV0VqbytFZ1piM3daSEt5d3QKMUVaVHBET1NKY29VeXZnWmFwUFF6U2JDZVdUL3ZlRW8rem5pUlk5SThFRlJhNm9DWDNCbVc4Snh2V2FSOVd3YQpnVUZ4cFM5OHdJN0JwSVJUeFgwdk9oMXZlUlBjWmRsVmFMZlJQb1BuV1BkdHAwckFDdXB6QWdNQkFBR2dBREFOCkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUllbTV5YnpVR1VvSk9yUjc1bW5COGZNUmVBWi9NalRVamYwem0xQjQKeGo4U1FMYTI2djU2ZkxOYkZ6NTlaaDlJa0J2U1AyNWNRTm5JU1lZT3RxejZLakJzcEVVQnNKaFVKcTNRNXpybgo3WVVoZnN2NWIzN0h2Y3h6akpvWW05NlZiU2FwQk5RWStGbjJ3R3NhZ1Zucktoalk0REdMM0lKQmlicmJvcEg2ClJwaFJRMWwyeXcwbUEybG9jK0hEZ1VwVTR4bXRpangvbHZmdHkzYVdwelBmV3pOWFRVYkEwNTFGY3hEQWh0SlkKbEd5WUxKSk1XQ08rL3NlUkxLSWFrZTFNeFR5Nzd0WVJ3MUNkVkJWWWFIbU8xM2k3ek8zYWVxdzloaGNHcWhyUQpXSWlYQ2lRdm9GN25oSmRvOEdmbkV5L1hKWk54LzQzbFVxUFcrekNhaWlsa2h3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t")
	block, _ := pem.Decode([]byte(data))
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	a, err := srv.SignCertificate(ctx, caType, newCA.Name, *csr)
	data2, _ := base64.StdEncoding.DecodeString(a)
	block2, _ := pem.Decode([]byte(data2))
	crt, _ := x509.ParseCertificate(block2.Bytes)

	testCases := []struct {
		name string
		cert secrets.Cert
		ret  error
	}{
		{"Delete deleted CA", newCAI, ErrDeleteCert},
		{"Delete certificate", newCA, nil},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			num := vault.InsertNth(vault.ToHexInt(crt.SerialNumber), 2)
			err = srv.DeleteCert(ctx, caType, tc.cert.Name, num)
			if err != nil {
				if tc.ret != err {
					if err.Error() != tc.ret.Error() {
						t.Errorf("Got result is %s; want %s", err, tc.ret)
					}
				}
			}

		})
	}
	if err != nil {
		t.Fatal("Could not delete certificate from file system")
	}
}

func setup(t *testing.T) (Service, context.Context) {
	t.Helper()

	buf := &bytes.Buffer{}
	logger := log.NewJSONLogger(buf)
	ctx := context.Background()
	ctx = context.WithValue(ctx, "LamassuLogger", logger)

	/*jcfg, err := jaegercfg.FromEnv()
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not load Jaeger configuration values fron environment")
		os.Exit(1)
	}
	level.Info(logger).Log("msg", "Jaeger configuration values loaded")

	tracer, closer, err := jcfg.NewTracer(
		jaegercfg.Logger(jaegerlog.StdLogger),
	)
	opentracing.SetGlobalTracer(tracer)

	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not start Jaeger tracer")
		os.Exit(1)
	}
	defer closer.Close()*/
	level.Info(logger).Log("msg", "Jaeger tracer started")

	vaultClient, err := mocks.NewVaultSecretsMock(t)
	if err != nil {
		t.Fatal("Unable to create Vault in-memory client")
	}

	vaultSecret, err := vault.NewVaultSecretsWithClient(
		vaultClient,
		"",
		"pki/lamassu/dev/",
		"",
		"",
		"",
		"",
		"",
		logger,
	)
	if err != nil {
		t.Fatal("Unable to create Vault in-memory service")
	}

	srv := NewCAService(logger, vaultSecret)
	return srv, ctx
}

func testCA(caName string) secrets.Cert {
	serialNumber := "23-33-5b-19-c8-ed-8b-2a-92-5c-7b-57-fc-47-45-e7-12-03-91-23"

	keyMetadata := secrets.KeyInfo{
		KeyType:     "rsa",
		KeyBits:     4096,
		KeyStrength: "",
	}

	subject := secrets.Subject{
		C:  "ES",
		ST: "Gipuzkoa",
		L:  "Locality",
		O:  "Organization",
		OU: "OrganizationalUnit",
		CN: "CommonName",
	}

	certContent := secrets.CertContent{
		CerificateBase64: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNURENDQWZPZ0F3SUJBZ0lVZnRXcTVObnpXZHUrSHk2S1RTMmpWazcybzRjd0NnWUlLb1pJemowRUF3SXcKY3pFTE1Ba0dBMVVFQmhNQ1JWTXhFVEFQQmdOVkJBZ1RDRWRwY0hWNmEyOWhNUkV3RHdZRFZRUUhFd2hCY25KaApjMkYwWlRFaE1BNEdBMVVFQ2hNSFV5NGdRMjl2Y0RBUEJnTlZCQW9UQ0V4TFV5Qk9aWGgwTVJzd0dRWURWUVFECkV4Sk1TMU1nVG1WNGRDQlNiMjkwSUVOQklETXdJQmNOTWpJd01USXdNVEV3TWpJMVdoZ1BNakExTWpBeE1UTXgKTVRBeU5UVmFNSE14Q3pBSkJnTlZCQVlUQWtWVE1SRXdEd1lEVlFRSUV3aEhhWEIxZW10dllURVJNQThHQTFVRQpCeE1JUVhKeVlYTmhkR1V4SVRBT0JnTlZCQW9UQjFNdUlFTnZiM0F3RHdZRFZRUUtFd2hNUzFNZ1RtVjRkREViCk1Ca0dBMVVFQXhNU1RFdFRJRTVsZUhRZ1VtOXZkQ0JEUVNBek1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMEQKQVFjRFFnQUU1aTFxZnlZU2xLaWt3SDhGZkhvQWxVWE44RlE3aE1OMERaTk8vVzdiSE44NVFpZ09ZeVQ1bWNYMgpXbDJtSTVEL0xQT1BKd0l4N1ZZcmxZU1BMTm5ndjZOak1HRXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01BOEdBMVVkCkV3RUIvd1FGTUFNQkFmOHdIUVlEVlIwT0JCWUVGUGRURSs3a0k2MXFXSHFtUktZai9OaElIS01lTUI4R0ExVWQKSXdRWU1CYUFGUGRURSs3a0k2MXFXSHFtUktZai9OaElIS01lTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUI2QQptZStjRzQ0MjBpNE5QZ1ZwWVRHN3hFN2lvbG0xOXhqRC9PcS9TeWt0QWlBaWRBK2JTanpvVHZxckRieDBqaHBiCmJpTnFycHZJY255TEY1MXQ5cHdBL1E9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t",
		PublicKeyBase64:  "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFNWkxcWZ5WVNsS2lrd0g4RmZIb0FsVVhOOEZRNwpoTU4wRFpOTy9XN2JITjg1UWlnT1l5VDVtY1gyV2wybUk1RC9MUE9QSndJeDdWWXJsWVNQTE5uZ3Z3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
	}

	cert := secrets.Cert{
		Status:       "issued",
		SerialNumber: serialNumber,
		Name:         caName,
		KeyMetadata:  keyMetadata,
		Subject:      subject,
		CertContent:  certContent,
		CaTTL:        2000,
		EnrollerTTL:  1000,
		ValidFrom:    "2022-01-31 15:00:08 +0000 UTC",
		ValidTo:      "2022-04-18 23:00:37 +0000 UTC",
	}
	return cert
}

func testCAImport() secrets.CAImport {
	return secrets.CAImport{
		PEMBundle: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUY2RENDQTlDZ0F3SUJBZ0lVQlVGWEFEa3NVaWY2d0xpOHVCejNvZzBMeDNFd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1ZURVBNQTBHQTFVRUJoTUdjM1J5YVc1bk1ROHdEUVlEVlFRSUV3WnpkSEpwYm1jeER6QU5CZ05WQkFjVApCbk4wY21sdVp6RVBNQTBHQTFVRUNoTUdjM1J5YVc1bk1ROHdEUVlEVlFRREV3WnpkSEpwYm1jd0hoY05Nakl3Ck1USXdNVFF4T0RNeFdoY05Nakl3TkRFek1qSXhPRFUzV2pCVk1ROHdEUVlEVlFRR0V3WnpkSEpwYm1jeER6QU4KQmdOVkJBZ1RCbk4wY21sdVp6RVBNQTBHQTFVRUJ4TUdjM1J5YVc1bk1ROHdEUVlEVlFRS0V3WnpkSEpwYm1jeApEekFOQmdOVkJBTVRCbk4wY21sdVp6Q0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCCkFMTE1lWS82K0RuZTYrajlJQzMyZERWeXluajl0bFU4Q1RNUVZnNnhpMXp1N24zOUd0TEE1eXFvMnpMYUt4bkcKY3lQQVRyQldHeHBGOHBBYXQrMGo5QWRuSGREV09SOW1ab0J1bWpOWjVFRElXSFoyTWhmQWtUcnZGVkRjMUgxKwo4Qnp0TnpiYjdVNUJUblFCTUJqY2prUUNhUlNaTzAwanpRQjhoQVFWcVNQZTRESVFwVWdET2hTVTduOUo5NXk3CktmZHpFN2NHSCtwR2RtZTVXZytYSHBOM2Vra1A0bHZLWlgxSHV6cXQvb1VtckM5QzVzNERnSjhjQ0VYM0NrK1kKSUsxM3VQZ3d4cFZuY0JHTU1rUTBnc3AzckxJQ21rbTZPMXVRRmpwd1RWMm94UUNVbkltUUF4V1pxRjlvY0sxegpRNkdZcTdUWnVvaGxQT1M1bmNHRHArMlY1OTR6bTh5cUtEVHJWTVFPY095YTlnZS8zaHg3N08rN05pYkhDclFlCmt3U2diR04zZFIxaVV0TDZvdFlSemYwYVV2bjBWSDRUUWFOVTR1c3BadDlwMFl2OTRzcnRjbHdGMk5PWHFqT3UKdlRrVFpObjRaTDJWYkRoWDdkcHp3Z1FKNmd4aERiblV5aWxTaUtqOVZ5bEdFdWY1YUxyckEySFc3NFFVQWlZcgpqb0xkOE9mVWR1YkxkS3RRZXB5UXpyVzk3WTZnOXZWOE82M0o1TWc4cnhBNGJ0K3NId3JKbmFPVGhhV3A3dWFXClhrVFNYWk55QUJ6cmYwOU5USkNMOXh6TFh3cWUwd05tZXR6bitacE8vR2N6c3AybDdMaFBCQlVyL3EvZk0yRUUKZ1Q3WUNubGtnZ0lGcVFpOFVkdUlyUkJiOWorRW45aVExemNRbWJDN3V5eGpBZ01CQUFHamdhOHdnYXd3RGdZRApWUjBQQVFIL0JBUURBZ0VHTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRkZxc3hZd0hqSUVMCjR1TlZCV3JZb2dCcXJRR1VNQjhHQTFVZEl3UVlNQmFBRkZxc3hZd0hqSUVMNHVOVkJXcllvZ0JxclFHVU1EWUcKQ0NzR0FRVUZCd0VCQkNvd0tEQW1CZ2dyQmdFRkJRY3dBWVlhYUhSMGNEb3ZMMlJsZGk1c1lXMWhjM04xTG1sdgpPamt3T1Rnd0VRWURWUjBSQkFvd0NJSUdjM1J5YVc1bk1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQ0FRQkptUTBMCmtaWTB5ajhTZXhnbEVyQTBpQW4vdlNyZVVIZE44anp5bGhzbDJ6WklIb0lQZ2ZjbnNrcktFQTZpdDlhUTJvNTEKMHA4YlhPOGtjb0xhMS93R1dSdm13TVBObHBmUDZRbjF1QkxGMnVHMkdyUEoyNGFUbUVOalRaaUxMRElxR3VUcwpPa1UvMU84eS9DdFJBWmlVR0RFM1RPRGN1eWlBNXAzYVVwc1VBZzA0cFdCWkFIN1p5cTdxMXNjYXdQczNpUFpaCkNVVmFRL3Z0Wmt6ckMzRFlJeDFFUmNHLzJLK3dTT0lIZTdYUlVZNi9jNkdjUXRwS2J2T2ZqR3QvcS9xWUJzSkUKRXRBS1hYbHJRSWJHYmVZdm9ZcWVwTUROV3VHQjBRZi8zcnVHZk93YU4vYUtZbW1icEtON0RYN3dDcVNTYkd2SApHdE5mNlZQVnJMSm8zZjFsSVg1bnBXRGQzNFF5TVpSNUNnbHdES2tKaGNmT0J3c1RBRTRMcEVRU0ZPTEx6QUI4CnNTTzg4b1BBTlR0UGhyMi9URk9DTlZIQVRJckNML3B6RUxmWDJmL2llSURtaXZ2WTB6UlJtZUVQbSt0bXhadnEKR21ZVlg0VVRDWTVQazVyUHRJZE1qNk5wcFNVaVo1WjkrTjBPUlBWSjhhdmV1UGVCcTdsUmVUNnlNUTFkREU4MwovRTZ4MThLMHR0dThMUVdVcXFHazZlVEVaMHdLMjhxMW03TmxuMDBCb1FGU2FNWnBKUXlEakp3dVVwQXhtTm0yCkdDZnI4azRBQ01VaUFaSG56M2RnY3RGTXJ2aVVIQ1QrMWxSOVJTenZ0Nk1IdjhuUVArM0YybzkzUUpMQnd0VXcKZTRKdGFFYWxadlV0LzFKZzVkd0Q4aytvcFQxRTZiQ3liOE8xZHc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t",
		TTL:       1000,
	}
}
