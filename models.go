package oauth2provider

import (
	"time"

	"github.com/credli/osin"
	"google.golang.org/appengine/datastore"
)

type ClientModel struct {
	Id          string `datastore:"id"`
	Name        string `datastore:"name"`
	RedirectUri string `datastore:"redirect_uri"`
	Active      bool   `datastore:"active"`
	GrantType   string `datastore:"grant_type"`
	Secret      string `datastore:"secret"`
}

type PPClient struct {
	Id          string `datastore:"id"`
	Name        string `datastore:"name"`
	Active      bool   `datastore:"active"`
	GrantType   string `datastore:"grant_type"`
	Secret      string `datastore:"secret"`
	RedirectUri string `datastore:"redirect_uri"`
	UserData    interface{}
}

func (d *PPClient) GetId() string {
	return d.Id
}

func (d *PPClient) GetSecret() string {
	return d.Secret
}

func (d *PPClient) GetRedirectUri() string {
	return d.RedirectUri
}

func (d *PPClient) GetUserData() interface{} {
	return d.UserData
}

func (d *PPClient) CopyFrom(client osin.Client) {
	d.Id = client.GetId()
	d.Secret = client.GetSecret()
	d.RedirectUri = client.GetRedirectUri()
	d.UserData = client.GetUserData()
}

type User struct {
	ID                    string    `json:"id" datastore:"id"`
	Username              string    `validate:"nonzero,min=3,max=40,regexp=^[a-z._]+$" json:"username" datastore:"username"`
	Password              string    `validate:"min=8" json:"password" datastore:"-"`
	PasswordHash          string    `json:"-" datastore:"password_hash"`
	FullName              string    `validate:"nonzero" json:"full_name" datatstore:"full_name"`
	Email                 string    `validate:"nonzero" json:"email" datastore:"email"`
	Phone                 string    `json:"-" datastore:"phone"`
	PhoneVerificationCode string    `json:"-" datastore:"phone_verification_code"`
	VerificationCode      string    `json:"-" datastore:"verification_code"`
	VerifiedAt            time.Time `json:"-" datastore:"verified_at"`
	SecretQuestion        string    `json:"-" datastore:"secret_question"`
	SecretAnswer          string    `json:"-" datastore:"secret_answer"`
	CreatedAt             time.Time `json:"-" datastore:"created_at"`
	LastLoginAt           time.Time `json:"last_login_at" datastore:"last_login_at"`
}

func (cl *ClientModel) GetId() string {
	return cl.Id
}

func (cl *ClientModel) GetSecret() string {
	return cl.Secret
}

// Base client uri
func (cl *ClientModel) GetRedirectUri() string { return cl.RedirectUri }

// Data to be passed to storage. Not used by the library.
func (cl *ClientModel) GetUserData() interface{} { return cl.GetUserData() }

func (c *ClientModel) ToClient() osin.Client {
	var client = &PPClient{
		Id:          c.Id,
		Secret:      c.Secret,
		RedirectUri: c.RedirectUri,
		UserData:    c,
	}
	return client
}

func FromClient(client osin.Client) *ClientModel {
	return &ClientModel{
		Id:          client.GetId(),
		Secret:      client.GetSecret(),
		RedirectUri: client.GetRedirectUri(),
	}
}

type AccessDataModel struct {
	UserKey             *datastore.Key `datastore:"user_key"`
	ClientID            string         `datastore:"client_id"`
	AuthorizationCode   string         `datastore:"authorization_code"`
	PreviousAccessToken string         `datastore:"prev_access_token"`
	AccessToken         string         `datastore:"access_token"`
	RefreshToken        string         `datastore:"refresh_token"`
	ExpiresIn           int32          `datastore:"expires_in"`
	Scope               string         `datastore:"scope"`
	RedirectUri         string         `datastore:"redirect_uri"`
	CreatedAt           time.Time      `datastore:"created_at"`
}

func (a *AccessDataModel) ToAccessData() *osin.AccessData {
	return &osin.AccessData{
		AccessToken:  a.AccessToken,
		RefreshToken: a.RefreshToken,
		ExpiresIn:    a.ExpiresIn,
		Scope:        a.Scope,
		RedirectUri:  a.RedirectUri,
		CreatedAt:    a.CreatedAt,
		UserData:     a.UserKey,
	}
}

func FromAccessData(data *osin.AccessData) *AccessDataModel {
	userKey, _ := data.UserData.(*datastore.Key)
	var ad = AccessDataModel{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		ExpiresIn:    data.ExpiresIn,
		Scope:        data.Scope,
		RedirectUri:  data.RedirectUri,
		CreatedAt:    data.CreatedAt,
		UserKey:      userKey,
	}
	if data.AuthorizeData == nil {
		// Client Credentials
		ad.AuthorizationCode = ""
	}
	return &ad
}

type AuthorizeModel struct {
	ClientID    string    `datastore:"client_id"`
	Code        string    `datastore:"code"`
	ExpiresIn   int32     `datastore:"expires_in"`
	Scope       string    `datastore:"scope"`
	RedirectUri string    `datastore:"redirect_uri"`
	State       string    `datastore:"state"`
	CreatedAt   time.Time `datastore:"created_at"`
}

func (a *AuthorizeModel) ToAuthorizeData() *osin.AuthorizeData {
	return &osin.AuthorizeData{
		Code:        a.Code,
		ExpiresIn:   a.ExpiresIn,
		Scope:       a.Scope,
		RedirectUri: a.RedirectUri,
		State:       a.State,
		CreatedAt:   a.CreatedAt,
	}
}

func FromAuthorizeData(auth *osin.AuthorizeData) *AuthorizeModel {
	return &AuthorizeModel{
		ClientID:    auth.Client.GetId(),
		Code:        auth.Code,
		ExpiresIn:   auth.ExpiresIn,
		Scope:       auth.Scope,
		RedirectUri: auth.RedirectUri,
		State:       auth.State,
		CreatedAt:   auth.CreatedAt,
	}
}
