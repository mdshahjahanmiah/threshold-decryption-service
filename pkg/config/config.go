package config

import (
	"flag"
	"github.com/mdshahjahanmiah/explore-go/logging"
)

type Config struct {
	HttpAddress    string
	KmsHttpAddress string
	LoggerConfig   logging.LoggerConfig
}

func Load() (Config, error) {
	fs := flag.NewFlagSet("", flag.ExitOnError)

	httpAddress := fs.String("http.public.address", "0.0.0.0:9002", "HTTP listen address for all specified endpoints.")
	kmsHttpAddress := fs.String("kms.http.public.address", "http://localhost:9001", "KMS HTTP listen address for all specified endpoints.")

	loggerConfig := logging.LoggerConfig{}
	fs.StringVar(&loggerConfig.CommandHandler, "logger.handler.type", "json", "handler type e.g json, otherwise default will be text type")
	fs.StringVar(&loggerConfig.LogLevel, "logger.log.level", "info", "log level wise logging with fatal log")

	config := Config{
		HttpAddress:    *httpAddress,
		KmsHttpAddress: *kmsHttpAddress,
		LoggerConfig:   loggerConfig,
	}

	return config, nil
}
