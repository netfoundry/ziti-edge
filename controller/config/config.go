/*
	Copyright NetFoundry, Inc.

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

package config

import (
	"bytes"
	"crypto/sha1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/identity/identity"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sessionTimeoutDefault = 10
	sessionTimeoutMin     = 1

	enrollmentDurationMin     = 5
	enrollmentDurationDefault = 1440
)

type Enrollment struct {
	SigningCert       identity.Identity
	SigningCertConfig identity.IdentityConfig
	SigningCertCaPem  []byte
	EdgeIdentity      EnrollmentOption
	EdgeRouter        EnrollmentOption
	OtfIdentity       OtfEnrollmentOption
}

type EnrollmentOption struct {
	DurationMinutes time.Duration
}

type OtfEnrollmentOption struct {
	DurationMinutes int
}

type Api struct {
	SessionTimeoutSeconds time.Duration
	Listener              string
	Advertise             string
	Identity              identity.Identity
	IdentityConfig        identity.IdentityConfig
	IdentityCaPem         []byte
	HttpTimeouts          HttpTimeouts
}

type WSApi struct {
	SessionTimeoutSeconds time.Duration
	Listener              string
	Advertise             string
	Identity              identity.Identity
	IdentityConfig        identity.IdentityConfig
	IdentityCaPem         []byte
	WriteTimeout          time.Duration
	ReadTimeout           time.Duration
	IdleTimeout           time.Duration
	PongTimeout           time.Duration
	PingInterval          time.Duration
	HandshakeTimeout      time.Duration
	ReadBufferSize        int
	WriteBufferSize       int
	EnableCompression     bool
	Valid                 bool
}

type Config struct {
	RootIdentityConfig identity.IdentityConfig
	RootIdentity       identity.Identity
	RootIdentityCaPem  []byte
	Enabled            bool
	Api                Api
	WSApi              WSApi
	Enrollment         Enrollment
	caPems             [][]byte
	caPemsBuf          []byte
	caPemsOnce         sync.Once
}

type HttpTimeouts struct {
	ReadTimeoutDuration       time.Duration
	ReadHeaderTimeoutDuration time.Duration
	WriteTimeoutDuration      time.Duration
	IdleTimeoutsDuration      time.Duration
}

func (c *Config) SessionTimeoutDuration() time.Duration {
	return c.Api.SessionTimeoutSeconds
}

func toHex(data []byte) string {
	var buf bytes.Buffer
	for i, b := range data {
		if i > 0 {
			_, _ = fmt.Fprintf(&buf, ":")
		}
		_, _ = fmt.Fprintf(&buf, "%02x", b)
	}
	return strings.ToUpper(buf.String())
}

func (c *Config) CaPems() []byte {
	c.caPemsOnce.Do(func() {
		buf := bytes.Buffer{}
		//dedupe chains
		pemMap := map[string][]byte{}
		for _, caChain := range c.caPems {
			rest := caChain
			for len(rest) != 0 {
				var block *pem.Block
				block, rest = pem.Decode(rest)

				if block != nil {
					hash := sha1.Sum(block.Bytes)
					fingerprint := toHex(hash[:])
					pemMap[fingerprint] = pem.EncodeToMemory(block)
				}
			}
		}

		i := 0
		for _, pemBytes := range pemMap {
			if i != 0 {
				buf.Write([]byte("\n"))
			}
			buf.Write(pemBytes)
			i++
		}
		c.caPemsBuf = buf.Bytes()
	})

	return c.caPemsBuf
}

func (c *Config) loadRootIdentity(fabricConfigMap map[interface{}]interface{}) error {
	var fabricIdentitySubMap map[interface{}]interface{}
	if value, found := fabricConfigMap["identity"]; found {
		fabricIdentitySubMap = value.(map[interface{}]interface{})
	} else {
		return errors.New("required configuration value [identity] missing")
	}

	if value, found := fabricIdentitySubMap["cert"]; found {
		c.RootIdentityConfig.Cert = value.(string)
	} else {
		return fmt.Errorf("required configuration value [identity.cert] is missing")
	}

	if value, found := fabricIdentitySubMap["server_cert"]; found {
		c.RootIdentityConfig.ServerCert = value.(string)
	} else {
		return fmt.Errorf("required configuration value [identity.server_cert] is missing")
	}

	if value, found := fabricIdentitySubMap["key"]; found {
		c.RootIdentityConfig.Key = value.(string)
	} else {
		return fmt.Errorf("required configuration value [identity.key] is missing")
	}

	if value, found := fabricIdentitySubMap["server_key"]; found {
		c.RootIdentityConfig.ServerKey = value.(string)
	} //allow "key" to be the default, this isn't an error

	if value, found := fabricIdentitySubMap["ca"]; found {
		c.RootIdentityConfig.CA = value.(string)
	}

	var err error
	if c.RootIdentityCaPem, err = ioutil.ReadFile(c.RootIdentityConfig.CA); err != nil {
		return fmt.Errorf("could not read file CA file from [identity.ca]")
	}

	c.caPems = append(c.caPems, c.RootIdentityCaPem)

	c.RootIdentity, err = identity.LoadIdentity(c.RootIdentityConfig)

	return err
}

func (c *Config) loadApiSection(edgeConfigMap map[interface{}]interface{}) error {
	c.Api = Api{}
	var err error

	if value, found := edgeConfigMap["api"]; found {
		submap := value.(map[interface{}]interface{})

		if value, found := submap["listener"]; found {
			c.Api.Listener = value.(string)
		} else {
			return errors.New("required configuration value [edge.api.listener] missing")
		}

		if value, found := submap["advertise"]; found {
			c.Api.Advertise = value.(string)
		} else {
			return errors.New("required configuration value [edge.api.advertise] missing")
		}

		var intValue = 0
		if value, found := submap["sessionTimeoutMinutes"]; found {
			intValue = value.(int)
		}

		if intValue < sessionTimeoutMin {
			intValue = sessionTimeoutDefault
			pfxlog.Logger().Warn("[edge.api.sessionTimeout] defaulted to " + strconv.Itoa(intValue))
		}

		c.Api.SessionTimeoutSeconds = time.Duration(intValue) * time.Minute

		var apiIdentitySubMap map[interface{}]interface{}
		if value, found = submap["identity"]; found {
			apiIdentitySubMap = value.(map[interface{}]interface{})
		}

		if err = c.loadAPIIdentity(apiIdentitySubMap, &c.Api); err != nil {
			return fmt.Errorf("error loading Edge API Identity: %s", err)
		}

		if err = c.loadHttpTimeouts(submap); err != nil {
			return fmt.Errorf("error loading Edge API Http Timeouts: %s", err)
		}

	} else {
		return errors.New("required configuration section [edge.api] missing")
	}

	return nil
}

func (c *Config) loadWSApiSection(edgeConfigMap map[interface{}]interface{}) error {
	c.WSApi = WSApi{}
	var err error

	if value, found := edgeConfigMap["wsapi"]; found {
		submap := value.(map[interface{}]interface{})

		if value, found := submap["listener"]; found {
			c.WSApi.Listener = value.(string)
		} else {
			return errors.New("required configuration value [edge.wsapi.listener] missing")
		}

		if value, found := submap["advertise"]; found {
			c.WSApi.Advertise = value.(string)
		} else {
			return errors.New("required configuration value [edge.wsapi.advertise] missing")
		}

		var intValue = 0
		if value, found := submap["sessionTimeoutMinutes"]; found {
			intValue = value.(int)
		}

		if intValue < sessionTimeoutMin {
			intValue = sessionTimeoutDefault
			pfxlog.Logger().Warn("[edge.wsapi.sessionTimeout] defaulted to " + strconv.Itoa(intValue))
		}

		c.WSApi.SessionTimeoutSeconds = time.Duration(intValue) * time.Minute

		var wsapiIdentitySubMap map[interface{}]interface{}
		if value, found = submap["identity"]; found {
			wsapiIdentitySubMap = value.(map[interface{}]interface{})
		}

		if err = c.loadWSAPIIdentity(wsapiIdentitySubMap, &c.WSApi); err != nil {
			return fmt.Errorf("error loading Edge WSAPI Identity: %s", err)
		}

		if v, found := submap["writeTimeout"]; found {
			if i, ok := v.(int); ok {
				c.WSApi.WriteTimeout = time.Second * time.Duration(i)
			} else {
				return errors.New("invalid 'writeTimeout' value")
			}
		}
		if v, found := submap["readTimeout"]; found {
			if i, ok := v.(int); ok {
				c.WSApi.ReadTimeout = time.Second * time.Duration(i)
			} else {
				return errors.New("invalid 'readTimeout' value")
			}
		}
		if v, found := submap["idleTimeout"]; found {
			if i, ok := v.(int); ok {
				c.WSApi.IdleTimeout = time.Second * time.Duration(i)
			} else {
				return errors.New("invalid 'idleTimeout' value")
			}
		}
		if v, found := submap["pongTimeout"]; found {
			if i, ok := v.(int); ok {
				c.WSApi.PongTimeout = time.Second * time.Duration(i)
			} else {
				return errors.New("invalid 'pongTimeout' value")
			}
		}
		if v, found := submap["pingInterval"]; found {
			if i, ok := v.(int); ok {
				c.WSApi.PingInterval = time.Second * time.Duration(i)
			} else {
				return errors.New("invalid 'pingInterval' value")
			}
		} else {
			c.WSApi.PingInterval = (c.WSApi.PongTimeout * 9) / 10
		}
		if v, found := submap["handshakeTimeout"]; found {
			if i, ok := v.(int); ok {
				c.WSApi.HandshakeTimeout = time.Second * time.Duration(i)
			} else {
				return errors.New("invalid 'handshakeTimeout' value")
			}
		}
		if v, found := submap["readBufferSize"]; found {
			if i, ok := v.(int); ok {
				c.WSApi.ReadBufferSize = i
			} else {
				return errors.New("invalid 'readBufferSize' value")
			}
		}
		if v, found := submap["writeBufferSize"]; found {
			if i, ok := v.(int); ok {
				c.WSApi.WriteBufferSize = i
			} else {
				return errors.New("invalid 'writeBufferSize' value")
			}
		}
		if v, found := submap["enableCompression"]; found {
			if i, ok := v.(bool); ok {
				c.WSApi.EnableCompression = i
			} else {
				return errors.New("invalid 'enableCompression' value")
			}
		}
		c.WSApi.Valid = true
	}

	return nil
}

func (c *Config) loadAPIIdentity(apiIdentitySubMap map[interface{}]interface{}, api *Api) error {
	//default to root identity value
	api.IdentityConfig = identity.IdentityConfig{
		Key:        c.RootIdentityConfig.Key,
		Cert:       c.RootIdentityConfig.Cert,
		ServerCert: c.RootIdentityConfig.ServerCert,
		ServerKey:  c.RootIdentityConfig.ServerKey,
		CA:         c.RootIdentityConfig.CA,
	}

	if apiIdentitySubMap != nil {
		if value, found := apiIdentitySubMap["server_cert"]; found {
			c.Api.IdentityConfig.ServerCert = value.(string)
		} else {
			return fmt.Errorf("configuration value [edge.api.identity.server_cert] is required if [edge.api.identity] is specified")
		}

		if value, found := apiIdentitySubMap["server_key"]; found {
			c.Api.IdentityConfig.ServerKey = value.(string)
		} else {
			return fmt.Errorf("configuration value [edge.api.identity.server_key] is required if [edge.api.identity] is specified")
		}

		if value, found := apiIdentitySubMap["ca"]; found {
			c.Api.IdentityConfig.CA = value.(string)
			var err error
			if c.Api.IdentityCaPem, err = ioutil.ReadFile(c.Api.IdentityConfig.CA); err != nil {
				return fmt.Errorf("could not read file CA file from [edge.api.identity.ca]")
			}
			c.caPems = append(c.caPems, c.Api.IdentityCaPem)
		}
	}

	var err error
	api.Identity, err = identity.LoadIdentity(api.IdentityConfig)

	return err
}

func (c *Config) loadWSAPIIdentity(wsapiIdentitySubMap map[interface{}]interface{}, wsapi *WSApi) error {
	//default to root identity value
	wsapi.IdentityConfig = identity.IdentityConfig{
		Key:        c.RootIdentityConfig.Key,
		Cert:       c.RootIdentityConfig.Cert,
		ServerCert: c.RootIdentityConfig.ServerCert,
		ServerKey:  c.RootIdentityConfig.ServerKey,
		CA:         c.RootIdentityConfig.CA,
	}

	if wsapiIdentitySubMap != nil {
		if value, found := wsapiIdentitySubMap["server_cert"]; found {
			c.WSApi.IdentityConfig.ServerCert = value.(string)
		} else {
			return fmt.Errorf("configuration value [edge.api.identity.server_cert] is required if [edge.api.identity] is specified")
		}

		if value, found := wsapiIdentitySubMap["server_key"]; found {
			c.WSApi.IdentityConfig.ServerKey = value.(string)
		} else {
			return fmt.Errorf("configuration value [edge.api.identity.server_key] is required if [edge.api.identity] is specified")
		}

		if value, found := wsapiIdentitySubMap["ca"]; found {
			c.WSApi.IdentityConfig.CA = value.(string)
			var err error
			if c.WSApi.IdentityCaPem, err = ioutil.ReadFile(c.Api.IdentityConfig.CA); err != nil {
				return fmt.Errorf("could not read file CA file from [edge.api.identity.ca]")
			}
			c.caPems = append(c.caPems, c.WSApi.IdentityCaPem)
		}
	}

	var err error
	wsapi.Identity, err = identity.LoadIdentity(wsapi.IdentityConfig)

	return err
}

func (c *Config) loadEnrollmentSection(edgeConfigMap map[interface{}]interface{}) error {
	c.Enrollment = Enrollment{}
	var err error

	if value, found := edgeConfigMap["enrollment"]; found {
		submap := value.(map[interface{}]interface{})

		if value, found := submap["signingCert"]; found {
			submap := value.(map[interface{}]interface{})
			c.Enrollment.SigningCertConfig = identity.IdentityConfig{}

			if value, found := submap["cert"]; found {
				c.Enrollment.SigningCertConfig.Cert = value.(string)
				certPem, err := ioutil.ReadFile(c.Enrollment.SigningCertConfig.Cert)
				if err != nil {
					pfxlog.Logger().WithError(err).Panic("unable to read [edge.enrollment.cert]")
				}
				//The signer is a valid trust anchor
				c.caPems = append(c.caPems, certPem)

			} else {
				return fmt.Errorf("required configuration value [edge.enrollment.cert] is missing")
			}

			if value, found := submap["key"]; found {
				c.Enrollment.SigningCertConfig.Key = value.(string)
			} else {
				return fmt.Errorf("required configuration value [edge.enrollment.key] is missing")
			}

			if value, found := submap["ca"]; found {
				c.Enrollment.SigningCertConfig.CA = value.(string)

				if c.Enrollment.SigningCertCaPem, err = ioutil.ReadFile(c.Enrollment.SigningCertConfig.CA); err != nil {
					return fmt.Errorf("could not read file CA file from [edge.enrollment.signingCert.ca]")
				}

				c.caPems = append(c.caPems, c.Enrollment.SigningCertCaPem)
			} //not an error if the signing cert's CA is already represented in the root [identity.ca]

			if c.Enrollment.SigningCert, err = identity.LoadIdentity(c.Enrollment.SigningCertConfig); err != nil {
				return fmt.Errorf("error loading [edge.enrollment.signingCert]: %s", err)
			}

		} else {
			return errors.New("required configuration section [edge.enrollment.signingCert] missing")
		}

		if value, found := submap["edgeIdentity"]; found {
			submap := value.(map[interface{}]interface{})

			var edgeIdentityDurationInt = 0
			if value, found := submap["durationMinutes"]; found {
				edgeIdentityDurationInt = value.(int)
			}

			if edgeIdentityDurationInt < enrollmentDurationMin {
				edgeIdentityDurationInt = enrollmentDurationDefault
			}

			c.Enrollment.EdgeIdentity = EnrollmentOption{DurationMinutes: time.Duration(edgeIdentityDurationInt) * time.Minute}

		} else {
			return errors.New("required configuration section [edge.enrollment.edgeIdentity] missing")
		}

		if value, found := submap["edgeRouter"]; found {
			submap := value.(map[interface{}]interface{})

			var edgeRouterDurationInt = 0
			if value, found := submap["durationMinutes"]; found {
				edgeRouterDurationInt = value.(int)
			}

			if edgeRouterDurationInt < enrollmentDurationMin {
				edgeRouterDurationInt = enrollmentDurationDefault
			}

			c.Enrollment.EdgeRouter = EnrollmentOption{DurationMinutes: time.Duration(edgeRouterDurationInt) * time.Minute}

		} else {
			return errors.New("required configuration section [edge.enrollment.edgeRouter] missing")
		}

		c.Enrollment.OtfIdentity = OtfEnrollmentOption{DurationMinutes: 720} // default
		if value, found := submap["otfIdentity"]; found {
			if value != nil {
				submap := value.(map[interface{}]interface{})

				var otfIdentityDurationInt = 0
				if value, found := submap["durationMinutes"]; found {
					otfIdentityDurationInt = value.(int)
				}

				c.Enrollment.OtfIdentity = OtfEnrollmentOption{DurationMinutes: otfIdentityDurationInt}
			}

			// } else {
			// c.Enrollment.OtfIdentity = OtfEnrollmentOption{DurationMinutes: 720}
		}

	} else {
		return errors.New("required configuration section [edge.enrollment] missing")
	}

	return nil
}

func (c *Config) loadHttpTimeouts(apiSubMap map[interface{}]interface{}) error {
	c.Api.HttpTimeouts = HttpTimeouts{
		ReadTimeoutDuration:       5 * time.Second,
		ReadHeaderTimeoutDuration: 0,
		WriteTimeoutDuration:      10 * time.Second,
		IdleTimeoutsDuration:      5 * time.Second,
	}

	if value, found := apiSubMap["httpTimeouts"]; found && value != nil {
		httpTimeoutsSubMap := value.(map[interface{}]interface{})

		if value, found := httpTimeoutsSubMap["readTimeoutMs"]; found {
			readTimeoutMs := value.(int)
			if readTimeoutMs < 0 {
				readTimeoutMs = 0
			}
			c.Api.HttpTimeouts.ReadTimeoutDuration = time.Duration(readTimeoutMs) * time.Millisecond
		} else {
			pfxlog.Logger().Warnf("[edge.api.httpTimeouts.readTimeoutMs] defaulted to %v", c.Api.HttpTimeouts.ReadTimeoutDuration.Milliseconds())
		}

		if value, found := httpTimeoutsSubMap["readHeaderTimeoutMs"]; found {
			readHeaderTimeoutMs := value.(int)
			if readHeaderTimeoutMs < 0 {
				readHeaderTimeoutMs = 0
			}

			c.Api.HttpTimeouts.ReadHeaderTimeoutDuration = time.Duration(readHeaderTimeoutMs) * time.Millisecond
		} else {
			pfxlog.Logger().Warnf("[edge.api.httpTimeouts.readHeaderTimeoutMs] defaulted to %v", c.Api.HttpTimeouts.ReadHeaderTimeoutDuration.Milliseconds())
		}

		if value, found := httpTimeoutsSubMap["writeTimeoutMs"]; found {
			writeTimeoutMs := value.(int)
			if writeTimeoutMs < 0 {
				writeTimeoutMs = 0
			}

			c.Api.HttpTimeouts.WriteTimeoutDuration = time.Duration(writeTimeoutMs) * time.Millisecond
		} else {
			pfxlog.Logger().Warnf("[edge.api.httpTimeouts.writeTimeoutMs] defaulted to %v", c.Api.HttpTimeouts.ReadHeaderTimeoutDuration.Milliseconds())
		}

		if value, found := httpTimeoutsSubMap["idleTimeoutMs"]; found {
			idleTimeoutMs := value.(int)
			if idleTimeoutMs < 0 {
				idleTimeoutMs = 0
			}

			c.Api.HttpTimeouts.IdleTimeoutsDuration = time.Duration(idleTimeoutMs) * time.Millisecond
		} else {
			pfxlog.Logger().Warnf("[edge.api.httpTimeouts.idleTimeoutMs] defaulted to %v", c.Api.HttpTimeouts.ReadHeaderTimeoutDuration.Milliseconds())
		}

	} else {
		pfxlog.Logger().Warn("using default edge.api.httpTimeouts, no config section found")
	}

	return nil
}

func LoadFromMap(cfgmap map[interface{}]interface{}) (*Config, error) {
	edgeConfig := &Config{
		Enabled: false,
	}

	var edgeConfigMap map[interface{}]interface{}

	if val, ok := cfgmap["edge"]; ok && val != nil {
		if edgeConfigMap, ok = val.(map[interface{}]interface{}); !ok {
			return nil, fmt.Errorf("expected map as edge configuration")
		}
	} else {
		return edgeConfig, nil
	}

	edgeConfig.Enabled = cfgmap != nil

	if !edgeConfig.Enabled {
		return edgeConfig, nil
	}

	var err error

	if err = edgeConfig.loadRootIdentity(cfgmap); err != nil {
		return nil, err
	}

	if err = edgeConfig.loadApiSection(edgeConfigMap); err != nil {
		return nil, err
	}

	if err = edgeConfig.loadWSApiSection(edgeConfigMap); err != nil {
		return nil, err
	}

	if err = edgeConfig.loadEnrollmentSection(edgeConfigMap); err != nil {
		return nil, err
	}

	return edgeConfig, nil
}
