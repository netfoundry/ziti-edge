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
)

// IdentityAuthenticators identity authenticators
//
// swagger:model identityAuthenticators
type IdentityAuthenticators struct {

	// cert
	Cert *IdentityAuthenticatorsCert `json:"cert,omitempty"`

	// updb
	Updb *IdentityAuthenticatorsUpdb `json:"updb,omitempty"`
}

// Validate validates this identity authenticators
func (m *IdentityAuthenticators) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCert(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdb(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IdentityAuthenticators) validateCert(formats strfmt.Registry) error {

	if swag.IsZero(m.Cert) { // not required
		return nil
	}

	if m.Cert != nil {
		if err := m.Cert.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cert")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityAuthenticators) validateUpdb(formats strfmt.Registry) error {

	if swag.IsZero(m.Updb) { // not required
		return nil
	}

	if m.Updb != nil {
		if err := m.Updb.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("updb")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *IdentityAuthenticators) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IdentityAuthenticators) UnmarshalBinary(b []byte) error {
	var res IdentityAuthenticators
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// IdentityAuthenticatorsCert identity authenticators cert
//
// swagger:model IdentityAuthenticatorsCert
type IdentityAuthenticatorsCert struct {

	// fingerprint
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Validate validates this identity authenticators cert
func (m *IdentityAuthenticatorsCert) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *IdentityAuthenticatorsCert) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IdentityAuthenticatorsCert) UnmarshalBinary(b []byte) error {
	var res IdentityAuthenticatorsCert
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// IdentityAuthenticatorsUpdb identity authenticators updb
//
// swagger:model IdentityAuthenticatorsUpdb
type IdentityAuthenticatorsUpdb struct {

	// username
	Username string `json:"username,omitempty"`
}

// Validate validates this identity authenticators updb
func (m *IdentityAuthenticatorsUpdb) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *IdentityAuthenticatorsUpdb) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IdentityAuthenticatorsUpdb) UnmarshalBinary(b []byte) error {
	var res IdentityAuthenticatorsUpdb
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}