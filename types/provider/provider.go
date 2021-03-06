package provider

import (
	"io/ioutil"

	"github.com/ovrclk/akash/types"
	"gopkg.in/yaml.v2"
)

type Provider struct {
	HostURI    string                    `yaml:"hostURI"`
	Attributes []types.ProviderAttribute `yaml:"attributes"`
}

func (prov *Provider) Parse(file string) error {
	contents, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal([]byte(contents), prov)
	if err != nil {
		return err
	}

	return nil
}
