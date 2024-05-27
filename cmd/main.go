package main

import (
	"github.com/mdshahjahanmiah/explore-go/di"
	eHttp "github.com/mdshahjahanmiah/explore-go/http"
	"github.com/mdshahjahanmiah/explore-go/logging"
	"github.com/mdshahjahanmiah/threshold-decryption-service/pkg/config"
	"github.com/mdshahjahanmiah/threshold-decryption-service/pkg/decrypt"
	"go.uber.org/dig"
	"log/slog"
)

func main() {
	c := di.New()

	c.Provide(func() (config.Config, error) {
		conf, err := config.Load()
		if err != nil {
			slog.Error("failed to load configuration", "err", err)
			return config.Config{}, err
		}
		return conf, nil
	})

	c.Provide(func(conf config.Config) (*logging.Logger, error) {
		logger, err := logging.NewLogger(conf.LoggerConfig)
		if err != nil {
			slog.Error("initializing logger", "err", err)
			return nil, err
		}

		return logger, nil
	})

	c.Provide(func(config config.Config) *eHttp.ServerConfig {
		return &eHttp.ServerConfig{
			HttpAddress: config.HttpAddress,
		}
	})

	c.Provide(func(config config.Config, logger *logging.Logger) (decrypt.Service, error) {
		service, err := decrypt.NewDecryptionService(config, logger)
		if err != nil {
			slog.Error("initializing decryption service", "err", err)
			return nil, err
		}
		return service, nil
	})

	c.ProvideMonitoringEndpoints("endpoint")

	c.Provide(decrypt.MakeHandler, dig.Group("endpoint"))

	c.Invoke(func(in struct {
		dig.In
		Conf         config.Config
		ServerConfig *eHttp.ServerConfig
		Endpoints    []eHttp.Endpoint `group:"endpoint"`
	}) {
		server := eHttp.NewServer(in.ServerConfig, in.Endpoints, nil)
		c.Provide(func() di.StartCloser { return server }, dig.Group("startclose"))
	})

	c.Start()
}
