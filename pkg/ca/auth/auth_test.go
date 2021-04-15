package auth

import (
	"crypto/rsa"
	"io/ioutil"
	"testing"

	"github.com/lamassuiot/enroller/pkg/ca/configs"
	"github.com/lamassuiot/enroller/pkg/enroller/crypto"

	stdjwt "github.com/dgrijalva/jwt-go"
)

func TestKf(t *testing.T) {
	auth := setup(t)
	key := loadAuthPublicKey(t)

	token := createJWTTtoken(t)

	authKey, err := auth.Kf(token)
	if err != nil {
		t.Errorf("Auth service returned an error: %s", err)
	}

	if !authKey.(*rsa.PublicKey).Equal(key) {
		t.Error("Key returned from Auth service is not correct")
	}
}

func createJWTTtoken(t *testing.T) *stdjwt.Token {
	t.Helper()
	token := stdjwt.NewWithClaims(stdjwt.SigningMethodRS256, &KeycloakClaims{
		Type:                      "Bearer",
		AuthorizedParty:           "lamassu-enroller",
		Nonce:                     "3353e747-c5f8-405e-81d6-4dc845394bad",
		AuthTime:                  1608654546,
		SessionState:              "86932f09-c705-44dd-9c30-5a0e31f94e93",
		AuthContextClassReference: "0",
		AllowedOrigins:            []string{"*"},
		RealmAccess:               Roles{RoleNames: []string{"offline_access", "admin", "uma_authorization"}},
		ResourceAccess:            Account{roles: []Roles{Roles{RoleNames: []string{"manage-account", "manage-account-links", "view-profile"}}}},
		Scope:                     "openid email profile",
		EmailVerified:             false,
		PreferredUsername:         "enroller",
	})
	return token
}

func loadAuthPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()

	fileKey, err := ioutil.ReadFile("testdata/keycloak.key")
	if err != nil {
		t.Fatal("Unable to read public key file")
	}

	key, err := crypto.ParseKeycloakPublicKey([]byte(crypto.PublicKeyHeader + "\n" + string(fileKey) + "\n" + crypto.PublicKeyFooter))
	if err != nil {
		t.Fatal("Unable to parse public key")
	}

	return key

}

func setup(t *testing.T) *auth {
	t.Helper()

	cfg, err := configs.NewConfig("catest")
	if err != nil {
		t.Fatal("Unable to get configuration variables")
	}

	return &auth{
		keycloakCA:       cfg.KeycloakCA,
		keycloakHost:     cfg.KeycloakHostname,
		keycloakPort:     cfg.KeycloakPort,
		keycloakProtocol: cfg.KeycloakProtocol,
		keycloakRealm:    cfg.KeycloakRealm,
	}
}
