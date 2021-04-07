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
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// TerminatorDetail terminator detail
//
// swagger:model terminatorDetail
type TerminatorDetail struct {
	BaseEntity

	// address
	// Required: true
	Address *string `json:"address"`

	// binding
	// Required: true
	Binding *string `json:"binding"`

	// cost
	// Required: true
	Cost TerminatorCost `json:"cost"`

	// dynamic cost
	// Required: true
	DynamicCost TerminatorCost `json:"dynamicCost"`

	// identity
	// Required: true
	Identity *string `json:"identity"`

	// precedence
	// Required: true
	Precedence TerminatorPrecedence `json:"precedence"`

	// router
	// Required: true
	Router *EntityRef `json:"router"`

	// router Id
	// Required: true
	RouterID *string `json:"routerId"`

	// service
	// Required: true
	Service *EntityRef `json:"service"`

	// service Id
	// Required: true
	ServiceID *string `json:"serviceId"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *TerminatorDetail) UnmarshalJSON(raw []byte) error {
	// AO0
	var aO0 BaseEntity
	if err := swag.ReadJSON(raw, &aO0); err != nil {
		return err
	}
	m.BaseEntity = aO0

	// AO1
	var dataAO1 struct {
		Address *string `json:"address"`

		Binding *string `json:"binding"`

		Cost TerminatorCost `json:"cost"`

		DynamicCost TerminatorCost `json:"dynamicCost"`

		Identity *string `json:"identity"`

		Precedence TerminatorPrecedence `json:"precedence"`

		Router *EntityRef `json:"router"`

		RouterID *string `json:"routerId"`

		Service *EntityRef `json:"service"`

		ServiceID *string `json:"serviceId"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.Address = dataAO1.Address

	m.Binding = dataAO1.Binding

	m.Cost = dataAO1.Cost

	m.DynamicCost = dataAO1.DynamicCost

	m.Identity = dataAO1.Identity

	m.Precedence = dataAO1.Precedence

	m.Router = dataAO1.Router

	m.RouterID = dataAO1.RouterID

	m.Service = dataAO1.Service

	m.ServiceID = dataAO1.ServiceID

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m TerminatorDetail) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	aO0, err := swag.WriteJSON(m.BaseEntity)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, aO0)
	var dataAO1 struct {
		Address *string `json:"address"`

		Binding *string `json:"binding"`

		Cost TerminatorCost `json:"cost"`

		DynamicCost TerminatorCost `json:"dynamicCost"`

		Identity *string `json:"identity"`

		Precedence TerminatorPrecedence `json:"precedence"`

		Router *EntityRef `json:"router"`

		RouterID *string `json:"routerId"`

		Service *EntityRef `json:"service"`

		ServiceID *string `json:"serviceId"`
	}

	dataAO1.Address = m.Address

	dataAO1.Binding = m.Binding

	dataAO1.Cost = m.Cost

	dataAO1.DynamicCost = m.DynamicCost

	dataAO1.Identity = m.Identity

	dataAO1.Precedence = m.Precedence

	dataAO1.Router = m.Router

	dataAO1.RouterID = m.RouterID

	dataAO1.Service = m.Service

	dataAO1.ServiceID = m.ServiceID

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this terminator detail
func (m *TerminatorDetail) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with BaseEntity
	if err := m.BaseEntity.Validate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBinding(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCost(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDynamicCost(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIdentity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrecedence(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRouter(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRouterID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateService(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServiceID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TerminatorDetail) validateAddress(formats strfmt.Registry) error {

	if err := validate.Required("address", "body", m.Address); err != nil {
		return err
	}

	return nil
}

func (m *TerminatorDetail) validateBinding(formats strfmt.Registry) error {

	if err := validate.Required("binding", "body", m.Binding); err != nil {
		return err
	}

	return nil
}

func (m *TerminatorDetail) validateCost(formats strfmt.Registry) error {

	if err := m.Cost.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("cost")
		}
		return err
	}

	return nil
}

func (m *TerminatorDetail) validateDynamicCost(formats strfmt.Registry) error {

	if err := m.DynamicCost.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("dynamicCost")
		}
		return err
	}

	return nil
}

func (m *TerminatorDetail) validateIdentity(formats strfmt.Registry) error {

	if err := validate.Required("identity", "body", m.Identity); err != nil {
		return err
	}

	return nil
}

func (m *TerminatorDetail) validatePrecedence(formats strfmt.Registry) error {

	if err := m.Precedence.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("precedence")
		}
		return err
	}

	return nil
}

func (m *TerminatorDetail) validateRouter(formats strfmt.Registry) error {

	if err := validate.Required("router", "body", m.Router); err != nil {
		return err
	}

	if m.Router != nil {
		if err := m.Router.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("router")
			}
			return err
		}
	}

	return nil
}

func (m *TerminatorDetail) validateRouterID(formats strfmt.Registry) error {

	if err := validate.Required("routerId", "body", m.RouterID); err != nil {
		return err
	}

	return nil
}

func (m *TerminatorDetail) validateService(formats strfmt.Registry) error {

	if err := validate.Required("service", "body", m.Service); err != nil {
		return err
	}

	if m.Service != nil {
		if err := m.Service.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("service")
			}
			return err
		}
	}

	return nil
}

func (m *TerminatorDetail) validateServiceID(formats strfmt.Registry) error {

	if err := validate.Required("serviceId", "body", m.ServiceID); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TerminatorDetail) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TerminatorDetail) UnmarshalBinary(b []byte) error {
	var res TerminatorDetail
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
