package gogae

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type authKeyType int

var authKey authKeyType

type AuthConfig struct {
	Project string
	Prefix  string
	OAuth   struct {
		ClientID     string
		ClientSecret string
		RedirectURL  string
		Scopes       []string
	}
	JWT struct {
		Secret string
	}
}

type AuthMiddleware struct {
	Config           AuthConfig
	tokenKey         [32]byte
	secretHash       []byte
	handler          http.Handler
	scopes           []string
	userLoadFunction func(context context.Context, config *oauth2.Config, token *oauth2.Token) (string, error)
	oauthConf        *oauth2.Config
	authPrefix       string
}

func NewAuthMiddleware(handler http.Handler, config AuthConfig, userLoadFunction func(context context.Context, config *oauth2.Config, token *oauth2.Token) (string, error), prefix string) *AuthMiddleware {
	r := &AuthMiddleware{
		Config:           config,
		handler:          handler,
		scopes:           config.OAuth.Scopes,
		userLoadFunction: userLoadFunction,
		authPrefix:       prefix,
	}
	if prefix == "" {
		r.authPrefix = "/auth/google"
	}
	h := sha256.New()
	copy(r.tokenKey[:], h.Sum([]byte(config.JWT.Secret)))
	h.Reset()
	r.secretHash = h.Sum(r.tokenKey[:])
	r.oauthConf = &oauth2.Config{
		ClientID:     r.Config.OAuth.ClientID,
		ClientSecret: r.Config.OAuth.ClientSecret,
		RedirectURL:  r.Config.OAuth.RedirectURL,
		Scopes:       r.scopes,
		Endpoint:     google.Endpoint,
	}
	return r
}

func getSessionFromContext(ctx context.Context) *DecryptedToken {
	v := ctx.Value(authKey)
	if v != nil {
		return v.(*DecryptedToken)
	} else {
		return nil
	}
}

func (s *AuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var log = httpLogger(log, r)
	if strings.HasPrefix(r.URL.Path, s.authPrefix) || strings.HasPrefix(r.URL.Path, "/favicon") {
		s.handler.ServeHTTP(w, r)
	} else {
		token, err := jws.ParseJWTFromRequest(r)
		if err != nil {
			ac, err := r.Cookie("JWTAuth")
			if err != nil {
				log.WithError(err).Error("Reading JWT token from cookie")
				http.Redirect(w, r, s.authPrefix+"/login", 302)
				return
			}
			rawToken, err := base64.RawStdEncoding.DecodeString(ac.Value)
			if err != nil {
				log.WithError(err).WithField("tokenData", ac.Value).Error("Reading base64 decoding JWT token")
				http.Redirect(w, r, s.authPrefix+"/login", 302)
				return
			}
			token, err = jws.ParseJWT(rawToken)
			if err != nil {
				log.WithError(err).WithField("rawToken", rawToken).Error("Reading json decoding JWT token")
				http.Redirect(w, r, s.authPrefix+"/login", 302)
				return
			}
		}
		err = token.Validate(s.secretHash, crypto.SigningMethodHS256)
		if err != nil {
			log.WithError(err).Error("Validating JWT token")
			http.Redirect(w, r, s.authPrefix+"/login", 302)
			return
		}
		// We got here, token is valid
		// Decrypt the user session
		var ses = token.Claims().Get("ses").(string)
		encrypted, err := base64.StdEncoding.DecodeString(ses)
		if err != nil {
			log.WithError(err).Error("Decoding JWT session")
			http.Redirect(w, r, s.authPrefix+"/login", 302)
			return
		}
		var decryptNonce [24]byte
		copy(decryptNonce[:], encrypted[:24])
		decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &s.tokenKey)
		if !ok {
			log.WithError(err).Error("Valid token with invalid session, something is highly fishy")
			http.Redirect(w, r, s.authPrefix+"/login", 302)
			return
		}
		session := UserSession{}
		err = json.Unmarshal(decrypted, &session)
		if err != nil {
			log.WithError(err).Error("Decoding JWT session")
			http.Redirect(w, r, s.authPrefix+"/login", 302)
			return
		}
		session.AuthMiddleware = s
		s.handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authKey, &DecryptedToken{Claims: token.Claims(), Session: session})))
	}
}

func (s *AuthMiddleware) addPaths(router *httprouter.Router) {
	router.GET(s.authPrefix+"/login", s.googleLogin)
	router.GET(s.authPrefix+"/callback", s.googleCallback)
	router.GET(s.authPrefix+"/status", s.googleStatus)
}

func (s *AuthMiddleware) googleLogin(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	expiration := time.Now().Add(15 * time.Minute)
	randomTokenBytes := make([]byte, 16, 16)
	_, _ = rand.Read(randomTokenBytes)
	randomToken := base64.URLEncoding.EncodeToString(randomTokenBytes)
	cookie := &http.Cookie{Name: "csrftoken", Value: randomToken, Expires: expiration}
	url := s.oauthConf.AuthCodeURL(randomToken)
	http.SetCookie(w, cookie)
	http.Redirect(w, r, url, 302)
}

func (s *AuthMiddleware) googleStatus(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var log = httpLogger(log, r)
	ac, err := r.Cookie("JWTAuth")
	if err != nil {
		log.WithError(err).Error("Reading JWT token")
	}
	rawToken, err := base64.RawStdEncoding.DecodeString(ac.Value)
	if err != nil {
		log.WithError(err).Error("Base64 decoding JWT token")
	}
	token, err := jws.ParseJWT(rawToken)
	if err != nil {
		log.WithError(err).Error("Parsing JWT token")
	}
	err = token.Validate(s.secretHash, crypto.SigningMethodHS256)
	if err != nil {
		log.WithError(err).Error("Validating JWT token")
	}
	res, err := token.Claims().MarshalJSON()
	if err != nil {
		log.WithError(err).Error("Serializing claims")
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(res)
}

type DecryptedToken struct {
	Claims  jwt.Claims
	Session UserSession
}
type UserInfo struct {
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	Link          string `json:"link"`
	Id            string `json:"id"`
	Hd            string `json:"hd"`
	VerifiedEmail bool   `json:"verified_email"`
}

type UserSession struct {
	Token          *oauth2.Token
	UserData       string
	AuthMiddleware *AuthMiddleware
}

func (s *AuthMiddleware) googleCallback(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var log = httpLogger(log, r)
	code := r.URL.Query().Get("code")
	csrf := r.URL.Query().Get("state")
	csrfCookie, err := r.Cookie("csrftoken")
	if err != nil {
		log.WithError(err).Error("Recovering csrf cookie")
		w.WriteHeader(403)
		return
	}
	if !strings.EqualFold(csrfCookie.Value, csrf) {
		log.WithError(err).Error("Invalid csrf cookie")
		w.WriteHeader(403)
		return
	}
	token, err := s.oauthConf.Exchange(r.Context(), code)
	if err != nil {
		log.WithError(err).Error("Exchanging authentication code with google")
		w.WriteHeader(403)
		return
	}
	req, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		log.WithError(err).Error("Getting user info")
		w.WriteHeader(403)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		log.WithField("status", response.Status).Error("Getting user info")
		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			println("Error reading response")
		}
		log.WithField("status", response.Status).WithField("data", string(data)).Error("Getting user info")
		w.WriteHeader(403)
		return
	}
	jsonParser := json.NewDecoder(response.Body)
	u := UserInfo{}
	err = jsonParser.Decode(&u)
	if err != nil {
		println("Error : " + err.Error())
		w.WriteHeader(403)
		return
	}
	userData, err := s.userLoadFunction(r.Context(), s.oauthConf, token)
	if err != nil {
		log.WithError(err).Error("User data access")
		w.WriteHeader(403)
		return
	}
	claims := jws.Claims{}
	claims.SetExpiration(token.Expiry)
	claims.SetIssuedAt(time.Now())
	claims.SetSubject(u.Email)
	claims.Set("profile", u)
	session := UserSession{
		Token:    token,
		UserData: userData,
	}
	// Encrypt user data
	rawSession, err := json.Marshal(session)
	if err != nil {
		log.WithError(err).Error("Marshalling session")
		w.WriteHeader(500)
		return
	}
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	encrypted := secretbox.Seal(nonce[:], rawSession, &nonce, &s.tokenKey)
	claims.Set("ses", encrypted)
	jwtToken, err := jws.NewJWT(claims, crypto.SigningMethodHS256).Serialize(s.secretHash)
	if err != nil {
		log.WithError(err).Error("Creating JWT token")
		w.WriteHeader(500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "JWTAuth", Value: base64.RawStdEncoding.EncodeToString(jwtToken), Expires: token.Expiry, Path: "/"})
	http.Redirect(w, r, "/", 302)
	log.WithField("user.email", u.Email).Info("User login success")
}
