package credentials

import (
	"io"
	"net/url"
	"strings"
)

// RefreshTokenProvider implements a provider with token credentials
type RefreshTokenProvider struct {
	creds TokenCredentials
}

// AuthorizationCodeProvider implements a provider with code credentials
type AuthorizationCodeProvider struct {
	creds CodeCredentials
}

// Retrieve receives a RefreshTokenProvider and provides headers
func (provider *RefreshTokenProvider) Retrieve() (io.Reader, error) {
	form := url.Values{}
	form.Add("grant_type", string(refreshTokenGrantType))
	form.Add("client_id", provider.creds.ClientID)
	form.Add("client_secret", provider.creds.ClientSecret)
	form.Add("refresh_token", provider.creds.RefreshToken)

	return strings.NewReader(form.Encode()), nil
}

// URL receives a RefreshTokenProvider and provides a URL
func (provider *RefreshTokenProvider) URL() string {
	return provider.creds.URL
}

// Retrieve receives a AuthorizationCodeProvider and provides headers
func (provider *AuthorizationCodeProvider) Retrieve() (io.Reader, error) {
	form := url.Values{}
	form.Add("grant_type", string(authorizationCodeGrantType))
	form.Add("code", provider.creds.Code)
	form.Add("client_id", provider.creds.ClientID)
	form.Add("client_secret", provider.creds.ClientSecret)
	form.Add("redirect_uri", provider.creds.RedirectURI)

	return strings.NewReader(form.Encode()), nil
}

// URL receives a AuthorizationCodeProvider and provides a URL
func (provider *AuthorizationCodeProvider) URL() string {
	return provider.creds.URL
}
