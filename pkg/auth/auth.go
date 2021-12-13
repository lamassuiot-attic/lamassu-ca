package auth

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	stdjwt "github.com/dgrijalva/jwt-go"
	"github.com/lamassuiot/lamassu-ca/pkg/utils"
	"github.com/lestrrat-go/jwx/jwk"
)

type Auth interface {
	Kf(token *stdjwt.Token) (interface{}, error)
	ClaimsFactory() stdjwt.Claims
}

type auth struct {
	OidcWellKnownUrl string
	OidcCA           string
}

type OidcWellKnown struct {
	Issuer  string `json:"issuer"`
	JwksUri string `json:"jwks_uri"`
}
type Claims struct {
	stdjwt.StandardClaims
}

var (
	errBadWellKnown        = errors.New("unable to fetch OIDC well known information")
	errBadWellKnownContent = errors.New("unable to parse OIDC well known information")
	errBadJwksUri          = errors.New("unable to fetch OIDC JWKS Uri")
	errBadJwksUriContent   = errors.New("unable to parse OIDC JWKS Uri")
	errBadJwksSet          = errors.New("unable to parse OIDC JWKS into JWKS set")
	errBadKey              = errors.New("unexpected JWT key signing method")
	errBadPublicKeyRaw     = errors.New("unable to parse JWKS raw public key")
	errBadPublicKeyBuild   = errors.New("unable to build JWKS public key")
	errNoPublicKey         = errors.New("unable to obtain a valid public key")
	errOidcCA              = errors.New("error reading OIDC CA")
)

func NewAuth(oidcWellKnownUrl string, oidcCA string) Auth {
	return &auth{
		OidcWellKnownUrl: oidcWellKnownUrl,
		OidcCA:           oidcCA,
	}
}

func (a *auth) ClaimsFactory() stdjwt.Claims {
	return &Claims{}
}

func (a *auth) Kf(token *stdjwt.Token) (interface{}, error) {

	if _, ok := token.Method.(*stdjwt.SigningMethodRSA); !ok {
		return nil, errBadKey
	}

	client := &http.Client{}

	if strings.HasPrefix(strings.ToLower(a.OidcWellKnownUrl), "https") {
		caCertPool, err := utils.CreateCAPool(a.OidcCA)
		if err != nil {
			return nil, errOidcCA
		}

		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
		}
	}

	r, err := client.Get(a.OidcWellKnownUrl)
	if err != nil {
		return nil, errBadWellKnown
	}

	var oidcWellKnown OidcWellKnown
	if err := json.NewDecoder(r.Body).Decode(&oidcWellKnown); err != nil {
		return nil, errBadWellKnownContent
	}

	r, err = client.Get(oidcWellKnown.JwksUri)
	if err != nil {
		return nil, errBadJwksUri
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, errBadJwksUriContent
	}
	set, err := jwk.Parse(bodyBytes)

	if err != nil {
		return nil, errBadJwksSet
	}

	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
		if err := key.Raw(&rawkey); err != nil {
			return nil, errBadPublicKeyRaw
		}

		// We know this is an RSA Key
		rsaPubKey, ok := rawkey.(*rsa.PublicKey)
		if !ok {
			return nil, errBadPublicKeyBuild
		}
		return rsaPubKey, nil
	}
	return nil, errNoPublicKey
}
