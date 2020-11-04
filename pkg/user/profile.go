package user

import (
	"encoding/json"
	"fmt"

	"github.com/sonr-io/p2p/pkg/lobby"
)

// Profile is Model with device, location, profile information
type Profile struct {
	// Management
	ID     string
	OLC    string
	Device string
	Status Status

	// Sensory Variables
	Direction float64
	Distance  float64
}

// NewProfile returns user object
func NewProfile(peerID string, olc string, device string) Profile {
	// Create User
	return Profile{
		ID:     peerID,
		OLC:    olc,
		Device: device,
		Status: Available,
	}
}

// State returns user State information as string
func (u *Profile) State() string {
	slice := [2]string{fmt.Sprintf("%f", u.Direction), string(u.Status)}
	bytes, err := json.Marshal(slice)

	// Check for Error
	if err != nil {
		println("Error creating update message")
	}

	return string(bytes)
}

// String returns user as json string
func (u *Profile) String() string {
	// Create user map
	m := make(map[string]string)
	m["id"] = u.ID
	m["olc"] = u.OLC
	m["device"] = u.Device
	m["status"] = u.Status.String()

	// Convert to JSON
	msgBytes, err := json.Marshal(m)
	if err != nil {
		println(err)
	}

	// Return String
	return string(msgBytes)
}

// Update takes json and updates status/direction
func (u *Profile) Update(data string) error {
	// Get Update from Json
	up := new(lobby.UpdateNotification)
	err := json.Unmarshal([]byte(data), up)
	if err != nil {
		fmt.Println("Sonr P2P Error: ", err)
		return err
	}

	// Set New Data
	u.Direction = float64(up.Direction)
	u.Status = GetStatus(up.Status)

	// Return Notification
	return nil
}
