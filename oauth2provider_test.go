package oauth2provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/aetest"
	"google.golang.org/appengine/datastore"
)

var (
	inst         aetest.Instance
	server       *AEServer
	userID       = "AFC22203-63A0-4812-9283-5376D304BB5D"
	username     = "test@test.com"
	password     = "testpass"
	clientID     = "47bef51d-1b4a-4028-b4a1-07dfe3116a9b"
	clientSecret = "aabbccdd"
	redirectURI  = "https://www.google.com/"
	accessToken  = "fakeaccesstoken"
	refreshToken = "fakerefreshtoken"
)

type basicAuth struct {
	Username string
	Password string
}

func TestMain(m *testing.M) {
	setUp()
	defer tearDown()

	os.Exit(m.Run())
}

func setUp() {
	server = NewServer()
	opt := aetest.Options{AppID: "auth", StronglyConsistentDatastore: true}
	var err error
	inst, err = aetest.NewInstance(&opt)
	if err != nil || inst == nil {
		log.Printf("ERROR: %v", fmt.Errorf("Failed to created aetest instance, %v", err))
		inst.Close()
	}
	r, err := inst.NewRequest("GET", "/", nil)
	if err != nil {
		log.Panicf("Failed to create request: %v", err)
		inst.Close()
	}
	c := appengine.NewContext(r)

	_, err = setupFakeClient(c)
	if err != nil {
		log.Panicf("Failed to create fake client: %v", err)
		inst.Close()
	}

	userKey, err := setupFakeUser(c)
	if err != nil {
		log.Panicf("Failed to create fake user: %v", err)
		inst.Close()
	}

	_, err = setupFakeAccessToken(c, userKey)
	if err != nil {
		log.Panicf("Failed to create fake access token: %v", err)
		inst.Close()
	}
}

func tearDown() {
	if inst != nil {
		inst.Close()
	}
}

//TestPasswordAuth tests password password grant, expects a valid token
func TestPasswordAuth(t *testing.T) {
	// construct new request
	credentialsBodyStr := fmt.Sprintf("username=%s&password=%s", url.QueryEscape(username), url.QueryEscape(password))
	r, err := newRequest("POST", "/token?grant_type=password", credentialsBodyStr, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, &basicAuth{clientID, clientSecret})
	if err != nil {
		t.Fatalf("Failed to create request, reason: %v", err)
	}

	w := httptest.NewRecorder()
	server.HandleToken(w, r)
	if w.Code != http.StatusOK {
		t.Fail()
	}

	res, err := parseResponseBody(w.Body.Bytes())
	if err != nil {
		t.Fail()
	}

	assert.NotNil(t, res, "No valid JSON response was detected")

	if res["error_description"] != nil {
		t.Fatalf("JSON response indicated an error: %s", res["error_description"])
	}

	assert.NotNil(t, res["access_token"], "Access token was not provided")
	assert.NotNil(t, res["refresh_token"], "Refresh token was not provided")
	assert.NotNil(t, res["expires_in"], "Expiry info was not provided")
}

//TestPasswordAuth tests token refreshing method, expects a response with newly created access token in JSON format
func TestRefreshToken(t *testing.T) {
	aurl := fmt.Sprintf("/token?grant_type=refresh_token&refresh_token=%s", url.QueryEscape(refreshToken))
	r, err := newRequest("GET", aurl, "", nil, &basicAuth{clientID, clientSecret})
	if err != nil {
		t.Fatalf("Failed to create request, reason: %v", err)
	}

	w := httptest.NewRecorder()
	server.HandleToken(w, r)
	if w.Code != http.StatusOK {
		t.Fail()
	}

	res, err := parseResponseBody(w.Body.Bytes())
	if err != nil {
		t.Fail()
	}

	assert.NotNil(t, res, "No valid JSON response was detected")

	if res["error_description"] != nil {
		t.Fatalf("JSON response indicated an error: %s", res["error_description"])
	}

	assert.NotNil(t, res["access_token"], "Access token was not provided")
	assert.NotNil(t, res["refresh_token"], "Refresh token was not provided")
	assert.NotNil(t, res["expires_in"], "Expiry info was not provided")
}

//TestTokenInfo invokes /appauth/tokenInfo and expects a JSON response having attributes compatible with Google Endpoints
func TestTokenInfo(t *testing.T) {
	aurl := fmt.Sprintf("/appauth/tokenInfo?access_token=%s", url.QueryEscape(accessToken))
	r, err := newRequest("GET", aurl, "", nil, &basicAuth{clientID, clientSecret})
	if err != nil {
		t.Fatalf("Failed to create request, reason: %v", err)
	}

	w := httptest.NewRecorder()
	server.HandleAppAuthTokenInfo(w, r)
	assert.Equal(t, http.StatusOK, w.Code, fmt.Sprintf("HTTP return code was %d, expected 200", w.Code))

	res, err := parseResponseBody(w.Body.Bytes())
	if err != nil {
		t.Fail()
	}

	assert.NotNil(t, res, "No valid JSON response was detected")

	if res["error_description"] != nil {
		t.Fatalf("JSON response indicated an error: %s", res["error_description"])
	}

	assert.NotNil(t, res["user_id"], "Attribute user_id was not found")
	assert.NotNil(t, res["email"], "Attribute email was not found")
	assert.NotNil(t, res["verified_email"], "Attribute verified_email was not found")
	assert.NotNil(t, res["issued_to"], "Attribute issued_to was not found")
	assert.NotNil(t, res["audience"], "Attribute audience was not found")
	assert.NotNil(t, res["scope"], "Attribute scope was not found")
	assert.NotNil(t, res["scope"], "Attribute scope was not found")
	assert.NotNil(t, res["expires_in"], "Attribute expires_in was not found")
	assert.NotNil(t, res["access_type"], "Attribute access_type was not found")

}

func setupFakeClient(c context.Context) (*datastore.Key, error) {
	cl := &ClientModel{
		Id:          clientID,
		Name:        "Test Client",
		Secret:      clientSecret,
		GrantType:   "password",
		RedirectUri: redirectURI,
		Active:      true,
	}
	k := datastore.NewKey(c, ClientKind, clientID, 0, nil)
	return datastore.Put(c, k, cl)
}

func setupFakeUser(c context.Context) (*datastore.Key, error) {
	u := &User{
		ID:        userID,
		FullName:  "Test User",
		Email:     username,
		Password:  password,
		CreatedAt: time.Now(),
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	u.PasswordHash = string(hash)
	k := datastore.NewKey(c, UserKind, u.ID, 0, nil)
	return datastore.Put(c, k, u)
}

func setupFakeAccessToken(c context.Context, userKey *datastore.Key) (*datastore.Key, error) {
	ad := &AccessDataModel{
		UserKey:             userKey,
		ClientID:            clientID,
		AuthorizationCode:   "",
		PreviousAccessToken: "fakepreviousaccesstoken",
		AccessToken:         accessToken,
		RefreshToken:        refreshToken,
		ExpiresIn:           3600,
		Scope:               "email",
		RedirectUri:         redirectURI,
		CreatedAt:           time.Now(),
	}
	key := datastore.NewKey(c, AccessDataKind, ad.AccessToken, 0, nil)
	return datastore.Put(c, key, ad)
}

func newRequest(method, url, body string, headers map[string]string, auth *basicAuth) (*http.Request, error) {
	bodyBuf := bytes.NewBufferString(body)
	r, err := inst.NewRequest(method, url, bodyBuf)
	if err != nil {
		return nil, err
	}
	if headers != nil {
		for k := range headers {
			r.Header.Add(k, headers[k])
		}
	}
	if auth != nil {
		r.SetBasicAuth(auth.Username, auth.Password)
	}
	return r, err
}

func newRequestAndContext(method, url, body string, headers map[string]string, auth *basicAuth) (*http.Request, context.Context, error) {
	r, err := newRequest(method, url, body, headers, auth)
	if err != nil {
		return nil, nil, err
	}
	c := appengine.NewContext(r)
	return r, c, nil
}

func parseResponseBody(body []byte) (map[string]interface{}, error) {
	var response map[string]interface{}
	err := json.Unmarshal(body, &response)
	return response, err
}
