package config

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/caarlos0/env/v6"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"net/http"
	"reflect"
)

type Config struct {
	ProxyPass        string `env:"PROXY_PASS" envDefault:"http://127.0.0.1:80/"`
	Key              string `env:"KEY,required"`
	ExternalIP       string `env:"EXTERNAL_IP"`
	ListenIP         string `env:"LISTEN_IP" envDefault:"0.0.0.0"`
	NetworkConfigURL string `env:"NETWORK_CONFIG_URL" envDefault:"https://ton.org/global.config.json"`
	Port             int    `env:"PORT" envDefault:"9306"`
	PrivateKey       []byte
}

func LoadConfig() (*Config, error) {
	var cfg Config
	if err := env.ParseWithFuncs(&cfg, map[reflect.Type]env.ParserFunc{}); err != nil {
		return nil, err
	}
	srvKey, err := getPrivateKey(cfg.Key)
	if err != nil {
		return nil, err
	}
	cfg.PrivateKey = srvKey.Seed()
	if cfg.ExternalIP == "" {
		cfg.ExternalIP, err = getPublicIP()
		if err != nil {
			return nil, err
		}
	}
	return &cfg, nil
}

func getPrivateKey(key string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes long")
	}
	seed := pbkdf2.Key(b, []byte("adnl"), 1, 32, sha256.New)
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey, nil
}

func getPublicIP() (string, error) {
	req, err := http.Get("http://ip-api.com/json/")
	if err != nil {
		return "", err
	}
	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}

	var ip struct {
		Query string
	}
	err = json.Unmarshal(body, &ip)
	if err != nil {
		return "", err
	}

	return ip.Query, nil
}
