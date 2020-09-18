# gin-crypt3-basicauth

Basic authorization middleware for [Gin](https://github.com/gin-gonic/gin) that supports crypt(3) hashed passwords.

## Installation

    go get github.com/osoderholm/gin-crypt3-basicauth
    
## Usage

Import the package as `c3ba`

```go
import (
    ...
    c3ba "https://github.com/osoderholm/gin-crypt3-basicauth"
    ...
)
```

Create a `map[string]string` of allowed users. This implementation is up to you.

Use the middleware

```go
router := gin.Default()
router.Use(c3ba.BasicAuth(usersMap))
```

Access the authenticated user from `gin.Context`

```go
authenticatedUser := c.MustGet(c3ba.AuthUserKey)
```

### Example

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
    
    r.GET("/", func(c *gin.Context) {
    	user := c.MustGet(c3ba.AuthUserKey)
        c.JSON(200, gin.H{
            "user": user,
        })
    })

    r.Run() 
}
```

### Creating hashes

crypt(3) hashes can be created in different ways. Below are some examples.

    # MD5
    printf "password" | mkpasswd --stdin --method=md5
    
    # SHA256
    printf "password" | mkpasswd --stdin --method=sha-256
    
    # SHA512
    printf "password" | mkpasswd --stdin --method=sha-512
