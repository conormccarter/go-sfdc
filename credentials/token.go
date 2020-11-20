package credentials

import (
	"io"
	"net/url"
	"strings"
)

type RefreshTokenProvider struct {
	creds TokenCredentials
}

type AuthorizationCodeProvider struct {
	creds CodeCredentials
}

func (provider *RefreshTokenProvider) Retrieve() (io.Reader, error) {
	form := url.Values{}
	form.Add("grant_type", string(refreshTokenGrantType))
	form.Add("client_id", provider.creds.ClientID)
	form.Add("client_secret", provider.creds.ClientSecret)
	form.Add("refresh_token", provider.creds.RefreshToken)

	return strings.NewReader(form.Encode()), nil
}

func (provider *RefreshTokenProvider) URL() string {
	return provider.creds.URL
}

func (provider *AuthorizationCodeProvider) Retrieve() (io.Reader, error) {
	form := url.Values{}
	form.Add("grant_type", string(authorizationCodeGrantType))
	form.Add("code", provider.creds.Code)
	form.Add("client_id", provider.creds.ClientID)
	form.Add("client_secret", provider.creds.ClientSecret)
	form.Add("redirect_uri", provider.creds.RedirectURI)

	return strings.NewReader(form.Encode()), nil
}

func (provider *AuthorizationCodeProvider) URL() string {
	return provider.creds.URL
}
