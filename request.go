package gogae

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
	"net/http"
	"time"
)

type RequestContext struct {
	Request        *http.Request
	Params         httprouter.Params
	JWTToken       *DecryptedToken
	UserDataJson   string
	Client         *http.Client
	Log            *logrus.Entry
	redirectTarget string
	redirectCode   int
}

func (r RequestContext) Redirect(target string, code int) (interface{}, int, error) {
	r.redirectTarget = target
	r.redirectCode = code
	return nil, code, nil
}

type Handler func(context RequestContext) (interface{}, int, error)

func (g Gogae) Handle(f Handler) func(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
		var log = httpLogger(log, r)
		session := getSessionFromContext(r.Context())
		rc := RequestContext{
			Request:      r,
			Params:       params,
			JWTToken:     session,
			UserDataJson: "",
			Log:          log,
		}
		token := session.Session.Token
		oldExpiry := token.Expiry
		rc.Client = g.Auth.oauthConf.Client(r.Context(), token)
		payload, code, err := f(rc)
		newExpiry := token.Expiry
		if newExpiry.After(oldExpiry) {
			// Token was refreshed, recreate JWT !
			claims := session.Claims
			claims.SetExpiration(token.Expiry)
			claims.SetIssuedAt(time.Now())
			if err != nil {
				log.WithError(err).Error("Serializing user data")
				goto AfterToken
			}
			session := UserSession{
				Token:    token,
				UserData: rc.UserDataJson,
			}
			// Encrypt user data
			rawSession, err := json.Marshal(session)
			if err != nil {
				log.WithError(err).Error("Marshalling session")
				goto AfterToken
			}
			var nonce [24]byte
			if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
				panic(err)
			}
			encrypted := secretbox.Seal(nonce[:], rawSession, &nonce, &g.Auth.tokenKey)
			claims.Set("ses", encrypted)
			jwtToken, err := jws.NewJWT(jws.Claims(claims), crypto.SigningMethodHS256).Serialize(g.Auth.secretHash)
			if err != nil {
				log.WithError(err).Error("Creating JWT token")
				goto AfterToken
			}
			http.SetCookie(w, &http.Cookie{Name: "JWTAuth", Value: base64.RawStdEncoding.EncodeToString(jwtToken), Expires: token.Expiry, Path: "/"})
		}
	AfterToken:
		if err != nil {
			if code == 0 {
				code = 500
			}
		}
		if rc.redirectTarget != "" {
			http.Redirect(w, r, rc.redirectTarget, rc.redirectCode)
			return
		}
		w.WriteHeader(code)
		if payload != nil {
			w.Header().Set("Content-Type", "application/json")
			err = json.NewEncoder(w).Encode(payload)
			if err != nil {
				log.WithError(err).Error("Error writing json to output")
			}
		}
	}
}
