package authn

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// StartAccessName accesses the user's existing credentials and returns a PublicKeyCredentialRequestOptions
func StartAccessName(c *gin.Context) {
	// get username
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
	}

	// Check if user exists and return error if it does not
	whoIs, err := s.cosmos.QueryName(username)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	}

	// Call Save to store the session data
	options, err := s.webauthn.SaveAuthenticationSession(c.Request, c.Writer, whoIs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	c.JSON(http.StatusOK, options)
}

// FinishAccessName handles the login of a credential and returns a PublicKeyCredentialResponse
func FinishAccessName(c *gin.Context) {
	// get username
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
	}

	// Finish the authentication session
	cred, err := s.webauthn.FinishAuthenticationSession(c.Request, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}

	// handle successful login
	c.JSON(http.StatusOK, cred)
}
