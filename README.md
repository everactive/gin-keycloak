# ginkeycloak

## Overview

*ginkeycloak* is a simple middleware for [Gin](https://github.com/gin-gonic/gin) that will take
a Bearer token and verify it with a Keycloak server.

It also provides a method that will get a token for a client from the Keycloak server. 

Clients are granted access by having the scope specified when constructing the Auth object.

## Usage

```
package main

import (
	"github.com/everactive/ginkeycloak"
)

func main() {
    engine := gin.New()
    // Other gin based setup
    
    a := auth.New("id", "secret", "host", "port", "scheme", "scope", "tokenIntrospectPath", logger)
    
    engine.Use(a.HandleFunc)
}
```

* `id` - The client id as assigned by the Keycloak server for this service account
* `secret` - The client secret as assigned by the Keycloak server for this service account
* `host` - The host name or IP (ex. keycloak.example.com OR 192.168.1.1)
* `port` - If empty string it will be based on the scheme
* `scheme` - If empty string it will default to "https" which will set the port to 443 if empty
* `scope` - This is the arbitrary scope defined by the Keycloak server that must be assigned to clients that expect to use this API
* `tokenIntrospectPath` - The token introspect path (ex. /auth/realms/iot/protocol/openid-connect/token/introspect) for this realm
* `logger` - A reduced interface for a logger that can be provided for error/trace messages
    
    ```
    type authLogger interface {
        Errorf(format string, args ...interface{})
        Tracef(format string, args ...interface{})
        Error(args ...interface{})
    }
    ```
  
## Tests

```shell
go test ./...
```
