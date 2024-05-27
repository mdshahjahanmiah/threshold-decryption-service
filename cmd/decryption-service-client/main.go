package main

import (
	"encoding/base64"
	"fmt"
	"github.com/mdshahjahanmiah/explore-go/logging"
	"github.com/mdshahjahanmiah/threshold-decryption-service/pkg/config"
	"github.com/mdshahjahanmiah/threshold-decryption-service/pkg/decrypt"
)

func main() {

	loggerConfig := logging.LoggerConfig{}
	config := config.Config{
		LoggerConfig: loggerConfig,
		HttpAddress:  "localhost:8080", KmsHttpAddress: "http://localhost:9001"}
	logger, _ := logging.NewLogger(loggerConfig)

	service, err := decrypt.NewDecryptionService(config, logger)
	if err != nil {
		logger.Fatal("initializing decryption service", "err", err)
	}
	pairing := service.PairingParams()

	// Generate a random G1 element for the ciphertext
	ciphertextElement := pairing.NewG1().Rand()
	ciphertextBytes := ciphertextElement.Bytes()
	ciphertext := base64.StdEncoding.EncodeToString(ciphertextBytes)

	// Print the generated values
	fmt.Println("Testing Ciphertext: ", ciphertext)
}
