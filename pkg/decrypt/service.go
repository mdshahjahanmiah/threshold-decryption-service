package decrypt

import (
	"encoding/base64"
	"fmt"
	"github.com/Nik-U/pbc"
	"github.com/mdshahjahanmiah/explore-go/logging"
	"github.com/mdshahjahanmiah/threshold-decryption-service/pkg/client"
	"github.com/mdshahjahanmiah/threshold-decryption-service/pkg/config"
	"github.com/pkg/errors"
	"log/slog"
	"math/big"
)

type Decrypt struct {
	Ciphertext string
	Share      string
}

type Service interface {
	PartialDecryption(ciphertext string, share string) (*pbc.Element, error)
	PairingParams() *pbc.Pairing
}

type decryptionService struct {
	config  config.Config
	logger  *logging.Logger
	Pairing *pbc.Pairing
}

// NewDecryptionService creates a new decryption service with the given configuration and logger.
func NewDecryptionService(config config.Config, logger *logging.Logger) (Service, error) {
	encodedParams, err := client.FetchPairingParams(config.KmsHttpAddress)
	if err != nil {
		logger.Error("failed to fetch pairing parameters from KMS", "error", err)
		return nil, err
	}

	params, err := DecodePairingParams(encodedParams)
	if err != nil {
		logger.Error("failed to decode pairing parameters", "error", err)
		return nil, err
	}

	pairing := params.NewPairing()
	if pairing == nil {
		logger.Error("failed to create pairing")
		return nil, errors.New("failed to create pairing")
	}

	return &decryptionService{
		config:  config,
		logger:  logger,
		Pairing: pairing,
	}, nil
}

// PartialDecryption performs a partial decryption of the given ciphertext using the given share.
func (ds *decryptionService) PartialDecryption(ciphertext string, share string) (*pbc.Element, error) {
	ds.logger.Debug("starting partial decryption")

	// Decode a PBC element from the base64-encoded ciphertext
	pbcElement, err := ds.decodeCipherText(ciphertext)
	if err != nil {
		ds.logger.Error("generating ciphertext", "err", err)
		return nil, err
	}

	ds.logger.Debug("ciphertext element generated", "element", pbcElement.String())

	// Decode a PBC element from the base64-encoded share
	shareElement, err := ds.decodeShare(share)
	if err != nil {
		ds.logger.Error("generating share", "err", err)
		return nil, err
	}

	ds.logger.Debug("share element generated", "element", shareElement.String())

	// Perform the partial decryption
	part := ds.Pairing.NewG1().PowZn(pbcElement, shareElement)
	ds.logger.Debug("partial decryption result", "result", part.String())

	return part, nil
}

// PairingParams returns the pairing parameters used by the decryption service.
func (ds *decryptionService) PairingParams() *pbc.Pairing {
	return ds.Pairing
}

// decodeShare decodes a base64-encoded share and generates a PBC element.
func (ds *decryptionService) decodeShare(share string) (*pbc.Element, error) {
	shareBytes, err := base64.StdEncoding.DecodeString(share)
	if err != nil {
		slog.Error("decoding share base64", "err", err)
		return nil, err
	}

	// Log the decoded bytes
	ds.logger.Debug("decoded share bytes", "bytes", shareBytes)

	shareInt := new(big.Int).SetBytes(shareBytes)
	shareElement := ds.Pairing.NewZr().SetBig(shareInt)

	if shareElement.Is0() {
		ds.logger.Error("share element is zero after SetBig")
		return nil, fmt.Errorf("share element is zero after SetBig")
	}

	ds.logger.Debug("share element generated", "element", shareElement.String())

	return shareElement, nil
}

// decodeCipherText decodes a base64-encoded ciphertext and generates a PBC element and pairing.
func (ds *decryptionService) decodeCipherText(ciphertext string) (*pbc.Element, error) {
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		ds.logger.Error("Error decoding ciphertext base64:", "err", err)
		return nil, err
	}

	// Log the decoded bytes
	ds.logger.Debug("decoded ciphertext bytes", "bytes", ciphertextBytes)

	// Create a new G1 element from the decoded ciphertext bytes
	ciphertextElement := ds.Pairing.NewG1().SetBytes(ciphertextBytes)

	if ciphertextElement.Is0() {
		ds.logger.Error("ciphertext element is zero after SetBytes")
		return nil, fmt.Errorf("ciphertext element is zero after SetBytes")
	}

	ds.logger.Debug("ciphertext element generated", "element", ciphertextElement.String())

	return ciphertextElement, nil
}

// DecodePairingParams decodes the base64-encoded pairing parameters
func DecodePairingParams(encodedParams string) (*pbc.Params, error) {
	paramsBytes, err := base64.StdEncoding.DecodeString(encodedParams)
	if err != nil {
		return nil, err
	}

	params, err := pbc.NewParamsFromString(string(paramsBytes))
	if err != nil {
		return nil, err
	}

	return params, nil
}
