package tls

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type PathConfig struct {
	Path struct {
		Out      string `yaml:"out"`
		MPC      string `yaml:"MPC"`
		Libsnark string `yaml:"libsnark"`
		Package  string `yaml:"package"`
	} `yaml:"path"`
	File struct {
		Circuit  string `yaml:"circuit"`
		Input    string `yaml:"input"`
		Name     string `yaml:"name"`
		Prover   string `yaml:"prover"`
		Verifier string `yaml:"verifier"`
	} `yaml:"file"`
	Package struct {
		Generator string `yaml:"generator"`
	}
}

func ReadConf(filename string) (*PathConfig, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c := &PathConfig{}
	err = yaml.Unmarshal(buf, c)
	if err != nil {
		return nil, fmt.Errorf("in file %q: %v", filename, err)
	}

	return c, nil
}
