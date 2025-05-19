package client

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v3"
)

// LoadFromYAML loads client configurations from a YAML file
func LoadFromYAML(filePath string) ([]Client, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not read YAML file: %v", err)
	}

	var clientsYAML ClientsYAML
	if err := yaml.Unmarshal(data, &clientsYAML); err != nil {
		return nil, fmt.Errorf("could not parse YAML: %v", err)
	}

	// Process any plaintext credentials in YAML
	for i := range clientsYAML.Clients {
		ProcessCredentials(&clientsYAML.Clients[i])
	}

	return clientsYAML.Clients, nil
}
