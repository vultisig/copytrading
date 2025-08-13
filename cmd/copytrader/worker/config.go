package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
	"github.com/vultisig/verifier/plugin/config"
	"github.com/vultisig/verifier/vault_config"
)

type CopytraderWorkerConfig struct {
	Redis              config.Redis              `mapstructure:"redis" json:"redis,omitempty"`
	Rpc                Rpc                       `mapstructure:"Rpc" json:"Rpc,omitempty"`
	Verifier           config.Verifier           `mapstructure:"verifier" json:"verifier,omitempty"`
	BlockStorage       vault_config.BlockStorage `mapstructure:"block_storage" json:"block_storage,omitempty"`
	VaultServiceConfig vault_config.Config       `mapstructure:"vault_service" json:"vault_service,omitempty"`
	Datadog            struct {
		Host string `mapstructure:"host" json:"host,omitempty"`
		Port string `mapstructure:"port" json:"port,omitempty"`
	} `mapstructure:"datadog" json:"datadog"`
	Database config.Database `mapstructure:"database" json:"database,omitempty"`
}

type Rpc struct {
	Ethereum rpcItem `mapstructure:"ethereum" json:"ethereum,omitempty"`
}

type rpcItem struct {
	URL string `mapstructure:"url" json:"url,omitempty"`
}

func GetConfigure() (*CopytraderWorkerConfig, error) {
	configName := os.Getenv("VS_CONFIG_NAME")
	if configName == "" {
		configName = "config"
	}
	return ReadConfig(configName)
}

func ReadConfig(configName string) (*CopytraderWorkerConfig, error) {
	viper.SetConfigName(configName)
	viper.AddConfigPath(".")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("fail to reading config file, %w", err)
	}
	var cfg CopytraderWorkerConfig
	err := viper.Unmarshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to decode into struct, %w", err)
	}
	return &cfg, nil
}
