/*
	Copyright 2019 Netfoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package gateway

import (
	"errors"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"github.com/netfoundry/ziti-foundation/identity/identity"
	"net"
	"net/url"
	"strconv"
)

type Config struct {
	Enabled        bool
	ApiProxy       ApiProxy
	Advertise      string
	Csr            Csr
	IdentityConfig identity.IdentityConfig
}

type Csr struct {
	Sans               *Sans  `yaml:"sans"`
	Country            string `yaml:"country"`
	Locality           string `yaml:"locality"`
	Organization       string `yaml:"organization"`
	OrganizationalUnit string `yaml:"organizationalUnit"`
	Province           string `yaml:"province"`
}

type ApiProxy struct {
	Enabled  bool
	Listener string
	Upstream string
}

func NewConfig() *Config {
	return &Config{}
}

func (config *Config) LoadConfigFromMap(configMap map[interface{}]interface{}) error {
	var err error
	config.Enabled = false

	var edgeConfigMap map[interface{}]interface{} = nil

	if val, ok := configMap["edge"]; ok && val != nil {
		config.Enabled = true
		if edgeConfigMap, ok = val.(map[interface{}]interface{}); !ok {
			return fmt.Errorf("expected map as edge configuration")
		}
	}

	config.loadIdentity(configMap)

	if err = config.loadApiProxy(edgeConfigMap); err != nil {
		return err
	}

	if err = config.loadCsr(edgeConfigMap); err != nil {
		return err
	}

	if err = config.loadListener(configMap); err != nil {
		return err
	}

	return nil
}

func (config *Config) LoadIdentity() (identity.Identity, error) {
	return identity.LoadIdentity(config.IdentityConfig)
}

func (config *Config) loadApiProxy(edgeConfigMap map[interface{}]interface{}) error {
	config.ApiProxy = ApiProxy{}

	if value, found := edgeConfigMap["apiProxy"]; found {
		submap := value.(map[interface{}]interface{})

		if submap == nil {
			config.ApiProxy.Enabled = false
			return nil
		}

		if value, found := submap["listener"]; found {
			config.ApiProxy.Listener = value.(string)

			if config.ApiProxy.Listener == "" {
				return errors.New("required value [edge.apiProxy.listener] is expected to be a string")
			}
		} else {
			return errors.New("required value [edge.apiProxy.listener] is missing")
		}

		if value, found := submap["upstream"]; found {
			config.ApiProxy.Upstream = value.(string)

			if config.ApiProxy.Upstream == "" {
				return errors.New("required value [edge.apiProxy.upstream] is expected to be a string")
			}
		} else {
			return errors.New("required value [edge.apiProxy.upstream] is missing")
		}

		config.ApiProxy.Enabled = true
	} else {
		config.ApiProxy.Enabled = false
	}

	return nil
}

func (config *Config) loadListener(rootConfigMap map[interface{}]interface{}) error {
	subArray := rootConfigMap["listeners"]

	listeners := subArray.([]interface{})

	if listeners == nil {
		return errors.New("could not find [listeners] section")
	}

	var edgeBinding map[interface{}]interface{}

	for i, value := range listeners {
		submap := value.(map[interface{}]interface{})

		if submap == nil {
			return errors.New("value [listeners[" + strconv.Itoa(i) + "]] is not a map")
		}

		if value, found := submap["binding"]; found {
			binding := value.(string)

			if binding == "edge" {
				if edgeBinding != nil {
					return errors.New("multiple edge listeners found in [listeners], only one is allowed")
				}
				edgeBinding = submap
			}
		}
	}

	if edgeBinding == nil {
		return errors.New("required binding [edge] not found in [listeners]")
	}

	if value, found := edgeBinding["options"]; found {
		submap := value.(map[interface{}]interface{})

		if submap == nil {
			return errors.New("required section [listeners.edge.options] is not a map")
		}

		if value, found := submap["advertise"]; found {
			advertise := value.(string)

			if advertise == "" {
				return errors.New("required value [listeners.edge.options.advertise] was not a string or was not found")
			}

			config.Advertise = advertise
		} else {
			return errors.New("required value [listeners.edge.options.advertise] was not found")
		}

	} else {
		return errors.New("required value [listeners.edge.options] not found")
	}

	return nil
}

func (config *Config) loadCsr(edgeConfigMap map[interface{}]interface{}) error {
	config.Csr = Csr{}

	if value, found := edgeConfigMap["csr"]; found {
		submap := value.(map[interface{}]interface{})

		if submap == nil {
			return errors.New("required section [edge.csr] is not a map")
		}

		if err := mapstructure.Decode(submap, &config.Csr); err != nil {
			return fmt.Errorf("failed to load [edge.csr]: %s", err)
		}

	} else {
		return errors.New("required section [edge.csr] not found")
	}

	for _, uristr := range config.Csr.Sans.UriAddresses {
		parsedUrl, err := url.Parse(uristr)
		if err != nil {
			return fmt.Errorf("invalid SAN URI ecountered in configuration file: %s", uristr)
		}
		config.Csr.Sans.UriAddressesParsed = append(config.Csr.Sans.UriAddressesParsed, parsedUrl)
	}

	for _, ipstr := range config.Csr.Sans.IpAddresses {
		ip := net.ParseIP(ipstr)
		if ip == nil {
			return fmt.Errorf("invalid SAN IP address ecountered in configuration file: %s", ipstr)
		}
		config.Csr.Sans.IpAddressesParsed = append(config.Csr.Sans.IpAddressesParsed, ip)
	}

	return nil
}

func (config *Config) loadIdentity(rootConfigMap map[interface{}]interface{}) {
	config.IdentityConfig = identity.IdentityConfig{}
	if value, found := rootConfigMap["identity"]; found {
		submap := value.(map[interface{}]interface{})
		if value, found := submap["key"]; found {
			config.IdentityConfig.Key = value.(string)
		}
		if value, found := submap["cert"]; found {
			config.IdentityConfig.Cert = value.(string)
		}
		if value, found := submap["server_cert"]; found {
			config.IdentityConfig.ServerCert = value.(string)
		}
		if value, found := submap["server_key"]; found {
			config.IdentityConfig.ServerKey = value.(string)
		}
		if value, found := submap["ca"]; found {
			config.IdentityConfig.CA = value.(string)
		}
	}
}