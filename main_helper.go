package gogae

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"net/http"
	"os"
)

type GogaeConfig struct {
	AuthConfig     AuthConfig
	CloudSQLConfig *CloudSQLConfig
}

type Gogae struct {
	Router *httprouter.Router
	Auth   *AuthMiddleware
	Db     *sql.DB
	Log    *logrus.Logger
}

func (g *Gogae) Start() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	g.Log.WithField("port", port).Info("Starting service")
	g.Log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), g.Auth))
}

func InitGogae(config GogaeConfig, userLoadFunction func(context context.Context, config *oauth2.Config, token *oauth2.Token) (string, error)) (Gogae, error) {
	router := httprouter.New()
	auth := NewAuthMiddleware(router, config.AuthConfig, userLoadFunction, config.AuthConfig.Prefix)
	auth.addPaths(router)
	if config.CloudSQLConfig != nil {
		var DSN string
		if os.Getenv("GAE_DEPLOYMENT_ID") != "" {
			DSN = fmt.Sprintf("%s:%s@unix(/cloudsql/%s)/%s?parseTime=true", config.CloudSQLConfig.User, config.CloudSQLConfig.Password, config.CloudSQLConfig.Instance, config.CloudSQLConfig.DbName)
		} else {
			DSN = fmt.Sprintf("%s:%s@/%s?parseTime=true", config.CloudSQLConfig.User, config.CloudSQLConfig.Password, config.CloudSQLConfig.DbName)
		}
		db, err := sql.Open("mysql", DSN)
		if err != nil {
			log.WithField("DSN", DSN).WithError(err).Fatal("Connecting to Mysql")
			return Gogae{Router: router, Auth: auth, Log: log}, err
		}
		return Gogae{Router: router, Auth: auth, Db: db, Log: log}, nil
	}
	return Gogae{Router: router, Auth: auth, Log: log}, nil
}
