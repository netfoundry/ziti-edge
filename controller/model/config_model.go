/*
	Copyright 2020 Netfoundry, Inc.

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
	"github.com/netfoundry/ziti-edge/controller/persistence"
	"github.com/netfoundry/ziti-edge/controller/validation"
	"github.com/netfoundry/ziti-foundation/storage/boltz"
	"github.com/pkg/errors"
	"github.com/xeipuuv/gojsonschema"
	"go.etcd.io/bbolt"
	"reflect"
)

type Config struct {
	BaseModelEntityImpl
	Name string
	Type string
	Data map[string]interface{}
}

func (entity *Config) toBoltEntityForCreate(tx *bbolt.Tx, handler Handler) (persistence.BaseEdgeEntity, error) {
	if entity.Type == "" {
		return nil, validation.NewFieldError("config type must be specified", persistence.FieldConfigType, entity.Type)
	}
	return entity.toBoltEntityForUpdate(tx, handler)
}

func (entity *Config) toBoltEntityForUpdate(tx *bbolt.Tx, handler Handler) (persistence.BaseEdgeEntity, error) {
	if entity.Type != "" {
		providedType := entity.Type
		configTypeStore := handler.GetEnv().GetStores().ConfigType
		if !configTypeStore.IsEntityPresent(tx, entity.Type) {
			id := configTypeStore.GetNameIndex().Read(tx, []byte(entity.Type))
			if id != nil {
				entity.Type = string(id)
			}

			if !configTypeStore.IsEntityPresent(tx, entity.Type) {
				return nil, validation.NewFieldError("invalid config type", persistence.FieldConfigType, providedType)
			}
		}
	}

	if entity.Type == "" {
		currentConfig, err := handler.GetEnv().GetHandlers().Config.readInTx(tx, entity.Id)
		if err != nil {
			return nil, err
		}
		entity.Type = currentConfig.Type
	}

	if configType, _ := handler.GetEnv().GetHandlers().ConfigType.readInTx(tx, entity.Type); configType != nil && len(configType.Schema) > 0 {
		schema, err := configType.GetCompiledSchema()
		if err != nil {
			return nil, err
		}
		jsonLoader := gojsonschema.NewGoLoader(entity.Data)
		result, err := schema.Validate(jsonLoader)
		if err != nil {
			return nil, err
		}
		if !result.Valid() {
			return nil, validation.NewSchemaValidationErrors(result)
		}
	}

	return &persistence.Config{
		BaseEdgeEntityImpl: *persistence.NewBaseEdgeEntity(entity.Id, entity.Tags),
		Name:               entity.Name,
		Type:               entity.Type,
		Data:               entity.Data,
	}, nil
}

func (entity *Config) toBoltEntityForPatch(tx *bbolt.Tx, handler Handler) (persistence.BaseEdgeEntity, error) {
	return entity.toBoltEntityForUpdate(tx, handler)
}

func (entity *Config) fillFrom(_ Handler, _ *bbolt.Tx, boltEntity boltz.BaseEntity) error {
	boltConfig, ok := boltEntity.(*persistence.Config)
	if !ok {
		return errors.Errorf("unexpected type %v when filling model config", reflect.TypeOf(boltEntity))
	}

	entity.fillCommon(boltConfig)
	entity.Name = boltConfig.Name
	entity.Type = boltConfig.Type
	entity.Data = boltConfig.Data
	return nil
}