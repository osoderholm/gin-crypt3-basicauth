# gin-crypt3-basicauth

Basic authorization middleware for [Gin](https://github.com/gin-gonic/gin) that supports crypt(3) hashed passwords.

## Installation

    go get github.com/osoderholm/gin-crypt3-basicauth
    
## Usage

```go
package main

import (
	"github.com/gin-gonic/gin"
    c3ba "github.com/osoderholm/gin-crypt3-basicauth"
)

func main() {
    // Allowed users
    users := map[string]string{
        "foo": "$1$QKcl8j2L$OMdLsMX.TpVdOJkfErQWe1",
        "bar": "$5$gHMJY2A9Gv$VMV0P/GWZ7TxzkjkR8eo3D5ft/Rq7wk60ouCxGFU321",
    }
    
    r := gin.Default()

    // Use the middleware
    r.Use(c3ba.BasicAuth(users))
    
    r.GET("/ping", func(c *gin.Context) {
    		c.JSON(200, gin.H{
    			"message": "pong",
    		})
    	})

    r.Run() 
}
```