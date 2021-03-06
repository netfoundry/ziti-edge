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

package model

import (
	"github.com/openziti/fabric/controller/models"
	"github.com/openziti/foundation/storage/boltz"
	"go.etcd.io/bbolt"
	"strings"
)

func NewConfigHandler(env Env) *ConfigHandler {
	handler := &ConfigHandler{
		baseHandler: newBaseHandler(env, env.GetStores().Config),
	}
	handler.impl = handler
	return handler
}

type ConfigHandler struct {
	baseHandler
}

func (handler *ConfigHandler) newModelEntity() boltEntitySink {
	return &Config{}
}

func (handler *ConfigHandler) Create(config *Config) (string, error) {
	return handler.createEntity(config)
}

func (handler *ConfigHandler) Read(id string) (*Config, error) {
	modelEntity := &Config{}
	if err := handler.readEntity(id, modelEntity); err != nil {
		return nil, err
	}
	return modelEntity, nil
}

func (handler *ConfigHandler) readInTx(tx *bbolt.Tx, id string) (*Config, error) {
	modelEntity := &Config{}
	if err := handler.readEntityInTx(tx, id, modelEntity); err != nil {
		return nil, err
	}
	return modelEntity, nil
}

func (handler *ConfigHandler) IsUpdated(field string) bool {
	return !strings.EqualFold(field, "type")
}

func (handler *ConfigHandler) Update(config *Config) error {
	return handler.updateEntity(config, handler)
}

func (handler *ConfigHandler) Patch(config *Config, checker boltz.FieldChecker) error {
	combinedChecker := &AndFieldChecker{first: handler, second: checker}
	return handler.patchEntity(config, combinedChecker)
}

func (handler *ConfigHandler) Delete(id string) error {
	return handler.deleteEntity(id)
}

type ConfigListResult struct {
	Configs []*Config
	models.QueryMetaData
}
