package decrypt

import (
	"context"
	"encoding/base64"
	"github.com/go-kit/kit/endpoint"
	eError "github.com/mdshahjahanmiah/explore-go/error"
	"github.com/mdshahjahanmiah/explore-go/logging"
	"net/http"
)

type PartialDecryptResponse struct {
	PartialDecryption string `json:"partial_decryption"`
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
