package gogae

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/oauth2"
	"os"
)

type GogaeConfig struct {
	AuthPrefix     string
	AuthConfig     AuthConfig
	CloudSQLConfig *CloudSQLConfig
}

func InitGogae(config GogaeConfig, userLoadFunction func(context context.Context, config *oauth2.Config, token *oauth2.Token) (string, error)) (*httprouter.Router, *AuthMiddleware, *sql.DB, error) {
	router := httprouter.New()
	auth := NewAuthMiddleware(router, config.AuthConfig, userLoadFunction, config.AuthPrefix)
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
			return router, auth, nil, err
		}
		return router, auth, db, nil
	}
	return router, auth, nil, nil
}
