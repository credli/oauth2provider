package oauth2provider

import (
	"errors"

	"golang.org/x/net/context"

	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"

	"github.com/credli/osin"
)

var (
	//ClientKind the datastore Client entity name
	ClientKind = "Client"
	//UserKind the datastore User entity name
	UserKind = "User"
	//AccessDataKind the datastore AccessData entity name
	AccessDataKind = "AccessData"
	//AuthorizeKind the datastore Authorize entity name
	AuthorizeKind = "Authorize"
)

//AEStorage an App Engine Datastore implementation of osin.Storage
type AEStorage struct {
}

//NewAEStorage returns a new AEStorage instance
func NewAEStorage() *AEStorage {
	return &AEStorage{}
}

//Clone implemented only for interface compliance, not used in our case
func (s *AEStorage) Clone() osin.Storage {
	return s
}

//Close implemented only for interface compliance, not used in our case
func (s *AEStorage) Close() {
}

func (s *AEServer) insertClient(c context.Context, clientID string, secret string, redirectURI string, name string, active bool) error {
	//var data map[string]osin.Client
	client := &ClientModel{
		Id:          clientID,
		Secret:      secret,
		RedirectUri: redirectURI,
		Name:        name,
		Active:      active,
	}

	if cl, err := s.storage.GetClient(c, client.GetId()); err != nil {
		cm := FromClient(client)
		key := datastore.NewKey(c, ClientKind, cm.GetId(), 0, nil)
		_, err := datastore.Put(c, key, cm)
		if err != nil {
			log.Errorf(c, "Error: %v", err)
			return err
		}
	} else {
		return s.SetClient(c, cl)
	}

	return nil
}

//GetClient retrieves client info from the datastore
func (s *AEStorage) GetClient(c context.Context, id string) (osin.Client, error) {
	key := datastore.NewKey(c, ClientKind, id, 0, nil)
	var client ClientModel
	err := datastore.Get(c, key, &client)
	if err != nil {

		return nil, errors.New("Client not found")
	}
	return client.ToClient(), nil
}

//SetClient stores the client info in the datastore
func (s *AEServer) SetClient(c context.Context, client osin.Client) error {
	cm := FromClient(client)

	cm.Id = client.GetId()
	cm.Secret = client.GetSecret()
	cm.RedirectUri = client.GetRedirectUri()

	key := datastore.NewKey(c, ClientKind, cm.GetId(), 0, nil)
	datastore.Put(c, key, cm)

	return nil
}

//SaveAuthorize stores authorization data by code
func (s *AEStorage) SaveAuthorize(c context.Context, data *osin.AuthorizeData) error {
	adm := FromAuthorizeData(data)
	key := datastore.NewKey(c, AuthorizeKind, adm.Code, 0, nil)
	_, err := datastore.Put(c, key, adm)
	return err
}

//LoadAuthorize loads authorize data by code
func (s *AEStorage) LoadAuthorize(c context.Context, code string) (*osin.AuthorizeData, error) {
	key := datastore.NewKey(c, AuthorizeKind, code, 0, nil)
	var am AuthorizeModel
	err := datastore.Get(c, key, &am)
	if err != nil {
		return nil, errors.New("Authorize not found")
	}
	var rauth = am.ToAuthorizeData()
	client, err := s.GetClient(c, am.ClientID)
	if err != nil {
		return nil, errors.New("Client not found")
	}
	rauth.Client = client
	return rauth, nil
}

//RemoveAuthorize removes authorization code from the datastore
func (s *AEStorage) RemoveAuthorize(c context.Context, code string) error {
	key := datastore.NewKey(c, AuthorizeKind, code, 0, nil)
	return datastore.Delete(c, key)
}

//SaveAccess stores access data model in the datastore
func (s *AEStorage) SaveAccess(c context.Context, data *osin.AccessData) error {
	client, err := s.GetClient(c, data.Client.GetId())
	if client == nil || err != nil {
		return errors.New("Client not found")
	}

	if data.AuthorizeData != nil {
		auth, err := s.LoadAuthorize(c, data.AuthorizeData.Code)
		if auth == nil || err != nil {
			return errors.New("Authorization not found")
		}
	}

	var token = FromAccessData(data)
	token.ClientID = client.GetId()

	key := datastore.NewKey(c, AccessDataKind, token.AccessToken, 0, nil)
	_, err = datastore.Put(c, key, token)
	return err
}

//LoadAccess loads access data by token
func (s *AEStorage) LoadAccess(c context.Context, code string) (*osin.AccessData, error) {
	log.Infof(c, "Access code: %s", code)
	key := datastore.NewKey(c, AccessDataKind, code, 0, nil)
	var token AccessDataModel
	err := datastore.Get(c, key, &token)
	if err != nil {
		return nil, errors.New("Access not found")
	}

	var rtoken = token.ToAccessData()
	client, err := s.GetClient(c, token.ClientID)
	if client == nil || err != nil {
		return nil, errors.New("Client not found")
	}
	rtoken.Client = client

	if token.AuthorizationCode != "" {
		auth, err := s.LoadAuthorize(c, token.AuthorizationCode)
		if auth == nil || err != nil {
			return nil, errors.New("Authorization not found")
		}
		rtoken.AuthorizeData = auth
	}

	return rtoken, nil
}

//RemoveAccess removes access token from the datastore
func (s *AEStorage) RemoveAccess(c context.Context, code string) error {
	key := datastore.NewKey(c, AccessDataKind, code, 0, nil)
	return datastore.Delete(c, key)
}

//LoadRefresh loads an access data by refresh token
func (s *AEStorage) LoadRefresh(c context.Context, code string) (*osin.AccessData, error) {
	q := datastore.NewQuery(AccessDataKind).Filter("refresh_token =", code)
	var accesses []*AccessDataModel
	keys, err := q.GetAll(c, &accesses)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("Refresh not found")
	}
	return s.LoadAccess(c, keys[0].StringID())
}

//RemoveRefresh removes refresh token from the database
func (s *AEStorage) RemoveRefresh(c context.Context, code string) error {
	q := datastore.NewQuery(AccessDataKind).Filter("refresh_token =", code)
	var accesses []*AccessDataModel
	keys, err := q.GetAll(c, &accesses)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("Refresh not found")
	}
	return s.RemoveAccess(c, keys[0].StringID())
}

//LoadUserFromAccessData loads user entity by userKey, this is used by /tokenInfo to determine user's email
func (s *AEStorage) LoadUserFromAccessData(c context.Context, data *osin.AccessData) (*User, error) {
	key, ok := data.UserData.(*datastore.Key)
	if !ok {
		return nil, errors.New("Access data does not belong to a user")
	}
	var u *User
	err := datastore.Get(c, key, &u)
	return u, err
}

//GetUser finds a user by username, this is used for password-based authentication
func (s *AEServer) GetUser(c context.Context, username string) (*User, error) {
	q := datastore.NewQuery(UserKind).Filter("username =", username)
	var users []*User
	_, err := q.GetAll(c, &users)
	if err != nil {
		return nil, err
		//return nil, errors.New("User not found")
	} else if len(users) > 0 {
		return users[0], nil
	}
	return nil, errors.New("User Not Found")
}
