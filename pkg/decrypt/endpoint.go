package decrypt

import (
	"context"
	"encoding/base64"
	"github.com/go-kit/kit/endpoint"
	eError "github.com/mdshahjahanmiah/explore-go/error"
	"github.com/mdshahjahanmiah/explore-go/logging"
	"net/http"
)

// CiphertextResponse is a response object for the generate ciphertext endpoint.
type CiphertextResponse struct {
	Ciphertext string `json:"ciphertext"`
}

// PartialDecryptResponse is a response object for the partial decryption endpoint.
type PartialDecryptResponse struct {
	PartialDecryption string `json:"partial_decryption"`
}

func getCiphertextEndpoint(logger *logging.Logger, service Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {

		ciphertext := service.GetCiphertext()
		if ciphertext == "" {
			logger.Error("fail to generate ciphertext")
			return nil, eError.NewServiceError(err, "fail to generate ciphertext", "ciphertext", http.StatusInternalServerError)
		}

		return CiphertextResponse{
			Ciphertext: ciphertext,
		}, nil
	}
}

func getPartialDecryptEndpoint(logger *logging.Logger, service Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		decryptRequest := request.(Decrypt)

		logger.Info("decrypt request", "ciphertext", decryptRequest.Ciphertext, "share", decryptRequest.Share)

		result, err := service.PartialDecryption(decryptRequest.Ciphertext, decryptRequest.Share)
		if err != nil {
			logger.Error("partial decryption failed", "err", err)
			return nil, eError.NewServiceError(err, "provided data could not be decrypted", "decrypt_request", http.StatusUnprocessableEntity)
		}

		// Encode the result as a base64 string
		partialDecryptionBytes := result.Bytes()
		encodedPartialDecryption := base64.StdEncoding.EncodeToString(partialDecryptionBytes)

		return PartialDecryptResponse{
			PartialDecryption: encodedPartialDecryption,
		}, nil
	}
}
