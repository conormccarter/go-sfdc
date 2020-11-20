package credentials

import (
	"errors"
	"io"
)

// PasswordCredentials is a structure for the OAuth credentials
// that are needed to authenticate with a Salesforce org.
//
// URL is the login URL used, examples would be https://test.salesforce.com or https://login.salesforce.com
//
// Username is the Salesforce user name for logging into the org.
//
// Password is the Salesforce password for the user.
//
// ClientID is the client ID from the connected application.
//
// ClientSecret is the client secret from the connected application.
type PasswordCredentials struct {
	URL          string
	Username     string
	Password     string
	ClientID     string
	ClientSecret string
}

// TokenCredentials is the token secret for the connected application.
type TokenCredentials struct {
	URL          string
	AccessToken  string
	RefreshToken string
	ClientID     string
	ClientSecret string
}

// CodeCredentials is the auth code secret for the connected application.
type CodeCredentials struct {
	URL          string
	Code  				string
	RedirectURI string
	ClientID     string
	ClientSecret string
}


// Credentials is the structure that contains all of the
// information for creating a session.
type Credentials struct {
	provider Provider
}

// Provider is the interface that is able to provide the
// session creator with all of the valid information.
//
// Retrieve will return the reader for the HTTP request body.
//
// URL is the URL base for the session endpoint.
type Provider interface {
	Retrieve() (io.Reader, error)
	URL() string
}

type grantType string

const (
	passwordGrantType grantType = "password"
	// authorization_code is used to get the first refresh_token
	authorizationCodeGrantType grantType = "authorization_code"
	// refresh_token is used to refresh an expired (15 min old) access token
	refreshTokenGrantType grantType = "refresh_token"
)

// Retrieve will return the reader for the HTTP request body.
func (creds *Credentials) Retrieve() (io.Reader, error) {
	return creds.provider.Retrieve()
}

// URL is the URL base for the session endpoint.
func (creds *Credentials) URL() string {
	return creds.provider.URL()
}

// NewCredentials will create a credential with the custom provider.
func NewCredentials(provider Provider) (*Credentials, error) {
	if provider == nil {
		return nil, errors.New("credentials: the provider can not be nil")
	}
	return &Credentials{
		provider: provider,
	}, nil
}

// NewPasswordCredentials will create a crendential with the password credentials.
func NewPasswordCredentials(creds PasswordCredentials) (*Credentials, error) {
	if err := validatePasswordCredentials(creds); err != nil {
		return nil, err
	}
	return &Credentials{
		provider: &passwordProvider{
			creds: creds,
		},
	}, nil
}

func validatePasswordCredentials(cred PasswordCredentials) error {
	if cred.URL == "" {
		return errors.New("credentials: password credential's URL can not be empty")
	}
	if cred.Username == "" {
		return errors.New("credentials: password credential's username can not be empty")
	}
	if cred.Password == "" {
		return errors.New("credentials: password credential's password can not be empty")
	}
	if cred.ClientID == "" {
		return errors.New("credentials: password credential's client ID can not be empty")
	}
	if cred.ClientSecret == "" {
		return errors.New("credentials: password credential's client secret can not be empty")
	}
	return nil
}

// NewTokenCredentials will create a credential with the password credentials.
func NewTokenCredentials(creds TokenCredentials) (*Credentials, error) {
	if err := validateTokenCredentials(creds); err != nil {
		return nil, err
	}
	return &Credentials{
		provider: &RefreshTokenProvider{
			creds: creds,
		},
	}, nil
}

// validateTokenCredentials ensures the required params are there,
// besides refresh (not always on the first run)
func validateTokenCredentials(cred TokenCredentials) error {
	if cred.URL == "" {
		return errors.New("credentials: token credential's URL can not be empty")
	}
	if cred.RefreshToken == "" {
		return errors.New("credentials: token credential's refresh token can not be empty")
	}
	if cred.ClientID == "" {
		return errors.New("credentials: token credential's client ID can not be empty")
	}
	if cred.ClientSecret == "" {
		return errors.New("credentials: token credential's client secret can not be empty")
	}
	return nil
}
