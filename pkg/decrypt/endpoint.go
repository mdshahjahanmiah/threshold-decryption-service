package decrypt

import (
	"context"
	"github.com/go-kit/kit/endpoint"
	eError "github.com/mdshahjahanmiah/explore-go/error"
	"github.com/mdshahjahanmiah/explore-go/logging"
	"net/http"
)

type DecryptionResult struct {
	X string `json:"x"`
	Y string `json:"y"`
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
		return DecryptionResult{X: result.X().String(), Y: result.Y().String()}, nil
	}
}
