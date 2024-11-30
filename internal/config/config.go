package config

import (
	"flag"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env           string              `yml:"env" env-default:"local"`
	UsersStorage  string              `yml:"usersstorage" env-required:"true"`
	TokensStorage TokensStorageConfig `yml:"tokensstorage" env-required:"true"`
	TokenTTL      time.Duration       `yml:"tokenttl" env-required:"true"`
	GRPC          GRPCConfig          `yml:"grpc" env-required:"true"`
}

type GRPCConfig struct {
	Port    int           `yml:"port"`
	Timeout time.Duration `yml:"timeout"`
}

type TokensStorageConfig struct {
	Addr     string `yml:"addr"`
	Password string `yml:"password"`
}

func MustLoad() *Config {
	path := fetchConfigPath()

	if path == "" {
		panic("config path is empty")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic("config file does not exist: " + path)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		panic("failed to read config: " + err.Error())
	}

	return &cfg
}

func fetchConfigPath() string {
	var res string

	flag.StringVar(&res, "config", "", "path to config")
	flag.Parse()
	if res == "" {
		res = os.Getenv("CONFIG_PATH")
	}
	return res
}
