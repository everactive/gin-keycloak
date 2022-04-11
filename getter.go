package ginkeycloak

import (
	"encoding/json"
	"time"

	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
)

const (
	tokenTruncateLengthForLog = 5
)

// TokenContainer provides a way to encapsulate the original Keycloak token and a convenience expiration time based on the ExpiresInSecond
type TokenContainer struct {
	KeycloakToken *Token
	ExpiresAt     time.Time
}

// Token is the token structure returned by the Keycloak server
type Token struct {
	AccessToken      string `json:"access_token"`
	ExpiresInSeconds int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int64  `json:"not-before-policy"`
	Scope            string `json:"scope"`
}

// TokenGetter is a wrapper to get the actual token
type TokenGetter struct {
	clientID             string
	clientSecret         string
	clientAccessTokenURL string
	log                  AuthLogger
	restyClient          *resty.Client
	tokenContainer       *TokenContainer
}

// NewGetter creates the token getter based on the arguments passed
func NewGetter(clientID, clientSecret, clientAccessTokenURL string, logger AuthLogger) *TokenGetter {
	return &TokenGetter{
		clientID,
		clientSecret,
		clientAccessTokenURL,
		logger,
		resty.New(),
		nil,
	}
}

// GetToken actually makes the request from the Keycloak server for the token if one is needed (don't have one or expired)
func (g *TokenGetter) GetToken() (*TokenContainer, error) {
	token := &Token{}
	needNewToken := false
	if g.tokenContainer == nil {
		needNewToken = true
		log.Tracef("Getting new token because we don't have one yet")
	} else if time.Now().After(g.tokenContainer.ExpiresAt) {
		needNewToken = true
		log.Tracef("Getting a new token because the existing one expired")
	}

	if needNewToken {
		log.Tracef("Getting token")
		req := g.restyClient.R()
		req.SetHeader("Content-Type", "application/x-www-form-urlencoded").
			SetFormData(map[string]string{
				"client_id":     g.clientID,
				"client_secret": g.clientSecret,
				"grant_type":    "client_credentials",
			})

		postResponse, err := req.Post(g.clientAccessTokenURL)
		if err != nil {
			g.log.Error(err)
			return nil, err
		}

		err = json.Unmarshal(postResponse.Body(), token)
		if err != nil {
			g.log.Error(err)
			return nil, err
		}

		// create a copy of the token to modify it before logging
		tokenTrace := *token

		// make sure there actually was a token, otherwise no need to truncate it
		if len(tokenTrace.AccessToken) > tokenTruncateLengthForLog {
			tokenTrace.AccessToken = tokenTrace.AccessToken[:tokenTruncateLengthForLog]
		}

		g.log.Tracef("Token (actual token value truncated): %+v", tokenTrace)
		expiresAt := time.Now().Add(time.Duration(token.ExpiresInSeconds) * time.Second)
		g.log.Tracef("Expires at: %s", expiresAt.String())
		g.tokenContainer = &TokenContainer{
			KeycloakToken: token,
			ExpiresAt:     expiresAt,
		}
	}

	return g.tokenContainer, nil
}
