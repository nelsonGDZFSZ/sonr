package authn

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RegisterNameStart starts the registration process for webauthn on http
func StartRegisterName(w http.ResponseWriter, r *http.Request) {
	if username := c.Param("username"); username != "" {
		// Check if user exists and return error if it does
		if exists := s.cosmos.NameExists(username); exists {
			c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
		}

		// Save Registration Session
		options, err := s.webauthn.SaveRegistrationSession(c.Request, c.Writer, username, s.cosmos.AccountName())
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		c.JSON(http.StatusOK, options)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
	}
}

// FinishRegisterName handles the registration of a new credential
func (s *HighwayServer) FinishRegisterName(w http.ResponseWriter, r *http.Request) {
	// get username
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
	}

	// Finish Registration Session
	cred, err := s.webauthn.FinishRegistrationSession(c.Request, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}

	// define a message to create a did
	msg := rtv1.NewMsgRegisterName(s.cosmos.Address(), username, *cred)

	// broadcast a transaction from account `alice` with the message to create a did
	// store response in txResp
	txResp, err := s.cosmos.BroadcastRegisterName(msg)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
	}
	c.JSON(http.StatusOK, txResp)
}
