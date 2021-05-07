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
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// SessionEdgeRouter session edge router
//
// swagger:model sessionEdgeRouter
type SessionEdgeRouter struct {
	CommonEdgeRouterProperties

	// urls
	// Required: true
	Urls map[string]string `json:"urls"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *SessionEdgeRouter) UnmarshalJSON(raw []byte) error {
	// AO0
	var aO0 CommonEdgeRouterProperties
	if err := swag.ReadJSON(raw, &aO0); err != nil {
		return err
	}
	m.CommonEdgeRouterProperties = aO0

	// AO1
	var dataAO1 struct {
		Urls map[string]string `json:"urls"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.Urls = dataAO1.Urls

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m SessionEdgeRouter) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	aO0, err := swag.WriteJSON(m.CommonEdgeRouterProperties)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, aO0)
	var dataAO1 struct {
		Urls map[string]string `json:"urls"`
	}

	dataAO1.Urls = m.Urls

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this session edge router
func (m *SessionEdgeRouter) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with CommonEdgeRouterProperties
	if err := m.CommonEdgeRouterProperties.Validate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUrls(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SessionEdgeRouter) validateUrls(formats strfmt.Registry) error {

	if err := validate.Required("urls", "body", m.Urls); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this session edge router based on the context it is used
func (m *SessionEdgeRouter) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with CommonEdgeRouterProperties
	if err := m.CommonEdgeRouterProperties.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (m *SessionEdgeRouter) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SessionEdgeRouter) UnmarshalBinary(b []byte) error {
	var res SessionEdgeRouter
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
