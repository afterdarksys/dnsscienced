package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

// ConfigFile is the YAML configuration structure for the gRPC server.
type ConfigFile struct {
	Listen        string   `yaml:"listen"`
	MetricsListen string   `yaml:"metrics_listen"`
	APIKeys       []string `yaml:"api_keys"`
	TLSCert       string   `yaml:"tls_cert"`
	TLSKey        string   `yaml:"tls_key"`
	TLSClientCAs  string   `yaml:"tls_client_cas"`
}

func LoadConfig(path string) (*ConfigFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c ConfigFile
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
