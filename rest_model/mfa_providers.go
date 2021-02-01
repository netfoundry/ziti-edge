// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright NetFoundry, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// __          __              _
// \ \        / /             (_)
//  \ \  /\  / /_ _ _ __ _ __  _ _ __   __ _
//   \ \/  \/ / _` | '__| '_ \| | '_ \ / _` |
//    \  /\  / (_| | |  | | | | | | | | (_| | : This file is generated, do not edit it.
//     \/  \/ \__,_|_|  |_| |_|_|_| |_|\__, |
//                                      __/ |
//                                     |___/

package rest_model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// MfaProviders mfa providers
//
// swagger:model mfaProviders
type MfaProviders string

const (

	// MfaProvidersZiti captures enum value "ziti"
	MfaProvidersZiti MfaProviders = "ziti"
)

// for schema
var mfaProvidersEnum []interface{}

func init() {
	var res []MfaProviders
	if err := json.Unmarshal([]byte(`["ziti"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		mfaProvidersEnum = append(mfaProvidersEnum, v)
	}
}

func (m MfaProviders) validateMfaProvidersEnum(path, location string, value MfaProviders) error {
	if err := validate.EnumCase(path, location, value, mfaProvidersEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this mfa providers
func (m MfaProviders) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateMfaProvidersEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
