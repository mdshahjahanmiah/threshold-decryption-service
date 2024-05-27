package client

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
)

// PairingParamResponse represents the response structure for pairing parameters
type PairingParamResponse struct {
	Params string `json:"params"`
}

// FetchPairingParams fetches the pairing parameters from the Key Management Service
func FetchPairingParams(kmsURL string) (string, error) {
	resp, err := http.Get(kmsURL + "/pairing-param")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("failed to fetch pairing parameters from KMS")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Unmarshal the response body into PairingParamResponse struct
	var response PairingParamResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}

	// Return the base64-encoded pairing parameters
	return response.Params, nil
}
