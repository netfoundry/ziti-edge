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

// AuthenticatorDetail A singular authenticator resource
//
// swagger:model authenticatorDetail
type AuthenticatorDetail struct {
	BaseEntity

	// cert pem
	CertPem string `json:"certPem,omitempty"`

	// fingerprint
	Fingerprint string `json:"fingerprint,omitempty"`

	// identity
	// Required: true
	Identity *EntityRef `json:"identity"`

	// identity Id
	// Required: true
	IdentityID *string `json:"identityId"`

	// method
	// Required: true
	Method *string `json:"method"`

	// username
	Username string `json:"username,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *AuthenticatorDetail) UnmarshalJSON(raw []byte) error {
	// AO0
	var aO0 BaseEntity
	if err := swag.ReadJSON(raw, &aO0); err != nil {
		return err
	}
	m.BaseEntity = aO0

	// AO1
	var dataAO1 struct {
		CertPem string `json:"certPem,omitempty"`

		Fingerprint string `json:"fingerprint,omitempty"`

		Identity *EntityRef `json:"identity"`

		IdentityID *string `json:"identityId"`

		Method *string `json:"method"`

		Username string `json:"username,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.CertPem = dataAO1.CertPem

	m.Fingerprint = dataAO1.Fingerprint

	m.Identity = dataAO1.Identity

	m.IdentityID = dataAO1.IdentityID

	m.Method = dataAO1.Method

	m.Username = dataAO1.Username

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m AuthenticatorDetail) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	aO0, err := swag.WriteJSON(m.BaseEntity)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, aO0)
	var dataAO1 struct {
		CertPem string `json:"certPem,omitempty"`

		Fingerprint string `json:"fingerprint,omitempty"`

		Identity *EntityRef `json:"identity"`

		IdentityID *string `json:"identityId"`

		Method *string `json:"method"`

		Username string `json:"username,omitempty"`
	}

	dataAO1.CertPem = m.CertPem

	dataAO1.Fingerprint = m.Fingerprint

	dataAO1.Identity = m.Identity

	dataAO1.IdentityID = m.IdentityID

	dataAO1.Method = m.Method

	dataAO1.Username = m.Username

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this authenticator detail
func (m *AuthenticatorDetail) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with BaseEntity
	if err := m.BaseEntity.Validate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIdentity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIdentityID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMethod(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AuthenticatorDetail) validateIdentity(formats strfmt.Registry) error {

	if err := validate.Required("identity", "body", m.Identity); err != nil {
		return err
	}

	if m.Identity != nil {
		if err := m.Identity.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("identity")
			}
			return err
		}
	}

	return nil
}

func (m *AuthenticatorDetail) validateIdentityID(formats strfmt.Registry) error {

	if err := validate.Required("identityId", "body", m.IdentityID); err != nil {
		return err
	}

	return nil
}

func (m *AuthenticatorDetail) validateMethod(formats strfmt.Registry) error {

	if err := validate.Required("method", "body", m.Method); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this authenticator detail based on the context it is used
func (m *AuthenticatorDetail) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with BaseEntity
	if err := m.BaseEntity.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIdentity(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AuthenticatorDetail) contextValidateIdentity(ctx context.Context, formats strfmt.Registry) error {

	if m.Identity != nil {
		if err := m.Identity.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("identity")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AuthenticatorDetail) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AuthenticatorDetail) UnmarshalBinary(b []byte) error {
	var res AuthenticatorDetail
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
