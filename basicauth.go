package c3ba

import (
	"encoding/base64"
	"errors"
	"github.com/GehirnInc/crypt"
	"github.com/gin-gonic/gin"
	// crypt(3) algorithms
	_ "github.com/GehirnInc/crypt/md5_crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"log"
	"net/http"
	"strings"
)

// AuthUserKey is the key with which one can retrieve the authenticated apiUser from gin.Context
const AuthUserKey = "apiUser"

// ErrorCryptBasicAuthUnsupportedHash is thrown if a hash is not supported by the crypt library
var ErrorCryptBasicAuthUnsupportedHash = errors.New("unsupported crypt hash")

// BasicAuth is a basic authorization middleware for Gin with crypt(3) support.
// Takes in a map of users and password hashes where each key is a user and the value is the hashed password.
// Successfully authenticated users username is stored in gin.Context using AuthUserKey.
func BasicAuth(users map[string]string) gin.HandlerFunc {
	for _, hash := range users {
		if !crypt.IsHashSupported(hash) {
			log.Panic(ErrorCryptBasicAuthUnsupportedHash)
		}
	}

	return func(c *gin.Context) {
		user, found := validateAuthorizationCrypt(users, c.Request.Header.Get("Authorization"))
		if !found {
			// Credentials don't match, return 401 and abort handlers chain.
			c.Header("WWW-Authenticate", "")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// The user credentials were found, set users name to key AuthUserKey in this context, 
		// the authenticated users username can be read later using c.MustGet(gin.AuthUserKey).
		c.Set(AuthUserKey, user)
	}
}

// validateAuthorization compares provided basic auth with allowed user.
// Returns username if match and success status.
func validateAuthorizationCrypt(users map[string]string, basic string) (string, bool) {
	basicUser, basicPass, ok := getBasicUserAndPass(basic)
	if !ok {
		return "", false
	}
	for user, hash := range users {
		if user != basicUser {
			continue
		}
		c := crypt.NewFromHash(hash)
		err := c.Verify(hash, []byte(basicPass))
		if err == nil {
			return user, true
		}
	}
	return "", false
}

// getBasicUserAndPass decodes the basic authorization header data and extracts user and pass.
// Returns the user and password as well as boolean with success status.
func getBasicUserAndPass(basic string) (string, string, bool) {
	basicBase64 := strings.TrimPrefix(basic, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(basicBase64)
	if err != nil || len(decoded) == 0 {
		return "", "", false
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
