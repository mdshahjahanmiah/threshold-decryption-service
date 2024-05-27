package decrypt

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	eError "github.com/mdshahjahanmiah/explore-go/error"
)

type Request struct {
	Ciphertext string `json:"ciphertext"`
	Share      string `json:"share"`
}

func decodeDecryptRequest(ctx context.Context, request *http.Request) (interface{}, error) {
	decoder := json.NewDecoder(request.Body)

	var decryptRequest Request
	err := decoder.Decode(&decryptRequest)
	if err != nil {
		slog.Error("decode decrypt request", "err", err)
		return nil, eError.NewServiceError(err, "decode decrypt request", "payload", http.StatusBadRequest)
	}

	if decryptRequest.Ciphertext == "" {
		slog.Error("missing ciphertext")
		return nil, eError.NewServiceError(errors.New("ciphertext is empty"), "validation_error", "ciphertext", http.StatusBadRequest)
	}
	slog.Info("ciphertext", "ciphertext", decryptRequest.Ciphertext)

	if decryptRequest.Share == "" {
		slog.Error("missing share")
		return nil, eError.NewServiceError(errors.New("partial share is empty"), "validation_error", "share", http.StatusBadRequest)
	}
	slog.Info("ciphertext", "share", decryptRequest.Share)

	return Decrypt{
		Ciphertext: decryptRequest.Ciphertext,
		Share:      decryptRequest.Share,
	}, nil
}
