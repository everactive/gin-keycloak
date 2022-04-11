// Package ginkeycloak provides a Gin Middleware for authorizing a client with a client credential grant and scope
package ginkeycloak

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
)

// RequestContext is an interface to satisfy the needs of the internal auth requests
type RequestContext interface {
	GetHeader(key string) string
	AbortWithStatusJSON(code int, jsonObj interface{})
	Next()
}

// AuthLogger is a minimal logger interface that is used inside the package
type AuthLogger interface {
	Errorf(format string, args ...interface{})
	Tracef(format string, args ...interface{})
	Error(args ...interface{})
}

// Auth is the struct to hold details for the client credentials grant and provides the middleware function
type Auth struct {
	clientID            string
	clientSecret        string
	host                string
	port                string
	scheme              string
	scope               string
	log                 AuthLogger
	tokenIntrospectPath string
	restyClient         *resty.Client
}

// New creates an Auth instance with a client for verifying tokens
func New(id, secret, host, port, scheme, scope, tokenIntrospectPath string, logger AuthLogger) *Auth {
	rc := resty.New()

	a := &Auth{
		id,
		secret,
		host,
		port,
		scheme,
		scope,
		logger,
		tokenIntrospectPath,
		rc,
	}

	if a.scheme == "" {
		a.scheme = "https"
	}

	if a.port == "" {
		a.port = "443"
	}

	return a
}

const (
	tokenHeaderParts                        = 2
	errorAuthHeaderIncorrectOrInvalidString = "authorization header incorrect or invalid, wrong number of parts"
	unknownErrorString                      = "unknown error encountered while trying to validate token"
)

var (
	errorAuthHeaderIncorrectOrInvalid = errors.New(errorAuthHeaderIncorrectOrInvalidString)
	ginUnknownErrorReturn             = gin.H{"error": unknownErrorString}
)

// ClientDetails are the minimum, necessary client details we need from the token
type ClientDetails struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope"`
	ClientID string `json:"clientId"`
}

func (a *Auth) getRawToken(authorizationHeader string) (string, error) {
	parts := strings.Split(authorizationHeader, " ")
	if len(parts) != tokenHeaderParts {
		a.log.Errorf("Authorization header incorrect: parts = %+v", parts)
		return "", errorAuthHeaderIncorrectOrInvalid
	}

	if parts[0] != "Bearer" {
		a.log.Errorf("Authorization header incorrect: parts = %+v", parts)
		return "", errorAuthHeaderIncorrectOrInvalid
	}

	return parts[1], nil
}

// HandleFunc is the Gin middleware function for handling client authentication via Bearer token
func (a *Auth) HandleFunc(context *gin.Context) {
	a.handleFuncInternal(context)
}

// VerifyTokenFromHeader will verify an Authorization string of the format "Bearer ......"
func (a *Auth) VerifyTokenFromHeader(header string) (bool, *ClientDetails, error) {
	token, err := a.getRawToken(header)
	if err != nil {
		// context.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return false, nil, err
	}
	realHost := a.host

	if a.port != "" {
		realHost = a.host + ":" + a.port
	}

	urlVar := url.URL{
		Scheme: a.scheme,
		Host:   realHost,
		Path:   a.tokenIntrospectPath,
	}

	req := a.restyClient.R()
	req.SetBasicAuth(a.clientID, a.clientSecret).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBody([]byte("token=" + token))

	a.log.Tracef(urlVar.String())

	resp, err := req.Post(urlVar.String())
	if err != nil {
		return false, nil, err
	}

	var cd ClientDetails
	err = json.Unmarshal(resp.Body(), &cd)
	if err != nil {
		a.log.Error(err)
		return false, nil, err
	} else if cd.Active && strings.Contains(cd.Scope, a.scope) {
		a.log.Tracef("Authorized client: %s", cd.ClientID)
		return true, &cd, nil
	}

	return false, nil, errors.New("unknown error encountered while trying to validate token")
}

func (a *Auth) handleFuncInternal(context RequestContext) {
	h := context.GetHeader("Authorization")

	authorized, clientDetails, err := a.VerifyTokenFromHeader(h)
	if err != nil {
		context.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	} else if authorized && clientDetails != nil {
		context.Next()
		return
	}

	context.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ginUnknownErrorReturn})
}
