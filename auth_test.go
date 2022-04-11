package ginkeycloak

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	"github.com/everactive/ginkeycloak/mocks"
)

type AuthTestSuite struct {
	suite.Suite
}

const (
	expectedClientID            = "client-id-123"
	expectedClientSecret        = "abc-123-def-4567-zxcv-9"
	expectedHost                = "auth.example.com"
	expectedPort                = "9000"
	expectedScheme              = "http"
	expectedScope               = "this-is-the-required-scope"
	expectedTokenIntrospectPath = "/some/path/to/token/introspect/path"
	expectedToken               = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJfeUFpTTc0UmFUZVBjT094QW0wT0Q5b0VyMHR3LXZ5MHhFaHQ3NG10ZmNnIn0.eyJleHAiOjE2NDIwMTYwMDAsImlhdCI6MTY0MjAxNTcwMCwianRpIjoiNDgwOGMzNzktMzI4OC00NzNiLTg3NDUtZjU3YWIzNTczMDI4IiwiaXNzIjoiaHR0cDovLzE5Mi4xNjguNTAuMjEwOjMwODAwL2F1dGgvcmVhbG1zL2RtcyIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI5ZDhhYjZmNi0zMzA5LTRiYzUtYjc2My0zYzkyMGEwZWI4ZWYiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJtYW5hZ2VtZW50IiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLWRtcyIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJpZGVudGl0eS1jbGllbnQiXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgaWRlbnRpdHktY2xpZW50IGVtYWlsIiwiY2xpZW50SG9zdCI6IjE5Mi4xNjguNTAuMjEwIiwiY2xpZW50SWQiOiJtYW5hZ2VtZW50IiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzZXJ2aWNlLWFjY291bnQtbWFuYWdlbWVudCIsImNsaWVudEFkZHJlc3MiOiIxOTIuMTY4LjUwLjIxMCJ9.fUOETo3b7OK8YnaWqnvg60syzuvJceHnfaZ8baFIorbVPcQbzIDkCKRMX5wtYBTIcWi8CwY53T1OI-Mt2TIfHHJb_YiucZz6i88paHP3LBTnY63xPagcMPZVkFohh7QMbjDNF9N52J9XDEjeLy5sbqCIxi2ndtOKJuSXQWahDK9xx_LSjXRYop1Jha05vuL36HigSsvH4dCoe2lTFm_OpgOAaeLxZvRdmV1ufdjeQFLfs7eDbsv3Npbb8o6zZ38A66OXtVW1yASQ64waw-PYox87AhkXUJWnnW4DYFn79f4968XuA2pH7ocDc5WSeEQG1h4E3JSMFpXLR3oyZ4m5qw"
)

func (s *AuthTestSuite) TestAuth_NewWithNoPortOrScheme() {
	a := New(expectedClientID, expectedClientSecret, expectedHost, "", "",
		expectedScope, expectedTokenIntrospectPath, logrus.StandardLogger())

	s.Assert().NotNil(a)
	s.Assert().Equal("443", a.port)
	s.Assert().Equal("https", a.scheme)
	s.Assert().Equal(expectedClientID, a.clientID)
	s.Assert().Equal(expectedClientSecret, a.clientSecret)
	s.Assert().Equal(expectedHost, a.host)
	s.Assert().Equal(expectedScope, a.scope)
	s.Assert().Equal(expectedTokenIntrospectPath, a.tokenIntrospectPath)
	s.Assert().Equal(logrus.StandardLogger(), a.log)
}

func (s *AuthTestSuite) TestAuth_NewWithPortAndScheme() {
	a := New(expectedClientID, expectedClientSecret, expectedHost, expectedPort, expectedScheme,
		expectedScope, expectedTokenIntrospectPath, logrus.StandardLogger())

	s.Assert().NotNil(a)
	s.Assert().Equal(expectedPort, a.port)
	s.Assert().Equal(expectedScheme, a.scheme)
	s.Assert().Equal(expectedClientID, a.clientID)
	s.Assert().Equal(expectedClientSecret, a.clientSecret)
	s.Assert().Equal(expectedHost, a.host)
	s.Assert().Equal(expectedScope, a.scope)
	s.Assert().Equal(expectedTokenIntrospectPath, a.tokenIntrospectPath)
	s.Assert().Equal(logrus.StandardLogger(), a.log)
}

func (s *AuthTestSuite) TestAuth_GetRawTokenWrongLength() {
	a := New(expectedClientID, expectedClientSecret, expectedHost, expectedPort, expectedScheme,
		expectedScope, expectedTokenIntrospectPath, logrus.StandardLogger())

	token, err := a.getRawToken("Bearer 123-456-789 extra-token-bit")
	s.Assert().Equal("", token)
	s.Assert().NotNil(err)
	s.Assert().Equal(errorAuthHeaderIncorrectOrInvalid, err)
}

func (s *AuthTestSuite) TestAuth_GetRawTokenWrongFirstToken() {
	a := New(expectedClientID, expectedClientSecret, expectedHost, expectedPort, expectedScheme,
		expectedScope, expectedTokenIntrospectPath, logrus.StandardLogger())

	token, err := a.getRawToken("Apple 123-456-789")
	s.Assert().Equal("", token)
	s.Assert().NotNil(err)
	s.Assert().Equal(errorAuthHeaderIncorrectOrInvalid, err)
}

func (s *AuthTestSuite) TestAuth_GetRawToken() {
	a := New(expectedClientID, expectedClientSecret, expectedHost, expectedPort, expectedScheme,
		expectedScope, expectedTokenIntrospectPath, logrus.StandardLogger())

	token, err := a.getRawToken("Bearer " + expectedToken)
	s.Assert().Equal(expectedToken, token)
	s.Assert().Nil(err)
}

func (s *AuthTestSuite) TestAuth_ValidToken() {
	a := New(expectedClientID, expectedClientSecret, expectedHost, expectedPort, expectedScheme,
		expectedScope, expectedTokenIntrospectPath, logrus.StandardLogger())

	mockedRequestContext := mocks.RequestContext{}

	mockedRequestContext.On("GetHeader", "Authorization").Return("Bearer " + expectedToken)
	mockedRequestContext.On("Next").Return()

	httpmock.ActivateNonDefault(a.restyClient.GetClient())
	defer httpmock.DeactivateAndReset()

	urlVar := url.URL{
		Scheme: a.scheme,
		Host:   expectedHost + ":" + expectedPort,
		Path:   a.tokenIntrospectPath,
	}

	httpmock.RegisterResponder("POST", urlVar.String(),
		httpmock.NewStringResponder(200, `{ "active": true, "scope": "`+expectedScope+`", "clientId": "`+expectedClientID+`" }`))

	a.handleFuncInternal(&mockedRequestContext)

	// As long as Next is called on our RequestContext the auth check succeeded (as expected)
	mockedRequestContext.AssertExpectations(s.T())
}

func (s *AuthTestSuite) TestAuth_InactiveOrInvalidToken() {
	a := New(expectedClientID, expectedClientSecret, expectedHost, expectedPort, expectedScheme,
		expectedScope, expectedTokenIntrospectPath, logrus.StandardLogger())

	mockedRequestContext := mocks.RequestContext{}

	mockedRequestContext.On("GetHeader", "Authorization").Return("Bearer " + expectedToken)
	mockedRequestContext.On("AbortWithStatusJSON", http.StatusInternalServerError, ginUnknownErrorReturn)

	httpmock.ActivateNonDefault(a.restyClient.GetClient())
	defer httpmock.DeactivateAndReset()

	urlVar := url.URL{
		Scheme: a.scheme,
		Host:   expectedHost + ":" + expectedPort,
		Path:   a.tokenIntrospectPath,
	}

	httpmock.RegisterResponder("POST", urlVar.String(),
		httpmock.NewStringResponder(200, `{ "active": false }`))

	a.handleFuncInternal(&mockedRequestContext)

	// As long as AbortWithStatusJSON is called on our RequestContext the auth check failed (as expected)
	mockedRequestContext.AssertExpectations(s.T())
}

func TestAuthTestSuite(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}
