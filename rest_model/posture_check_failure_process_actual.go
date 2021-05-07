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

// PostureCheckFailureProcessActual posture check failure process actual
//
// swagger:model postureCheckFailureProcessActual
type PostureCheckFailureProcessActual struct {

	// hash
	// Required: true
	Hash *string `json:"hash"`

	// is running
	// Required: true
	IsRunning *bool `json:"isRunning"`

	// os type
	OsType OsType `json:"osType,omitempty"`

	// path
	Path string `json:"path,omitempty"`

	// signer fingerprints
	// Required: true
	SignerFingerprints []string `json:"signerFingerprints"`
}

// Validate validates this posture check failure process actual
func (m *PostureCheckFailureProcessActual) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateHash(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsRunning(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOsType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSignerFingerprints(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PostureCheckFailureProcessActual) validateHash(formats strfmt.Registry) error {

	if err := validate.Required("hash", "body", m.Hash); err != nil {
		return err
	}

	return nil
}

func (m *PostureCheckFailureProcessActual) validateIsRunning(formats strfmt.Registry) error {

	if err := validate.Required("isRunning", "body", m.IsRunning); err != nil {
		return err
	}

	return nil
}

func (m *PostureCheckFailureProcessActual) validateOsType(formats strfmt.Registry) error {
	if swag.IsZero(m.OsType) { // not required
		return nil
	}

	if err := m.OsType.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("osType")
		}
		return err
	}

	return nil
}

func (m *PostureCheckFailureProcessActual) validateSignerFingerprints(formats strfmt.Registry) error {

	if err := validate.Required("signerFingerprints", "body", m.SignerFingerprints); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this posture check failure process actual based on the context it is used
func (m *PostureCheckFailureProcessActual) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateOsType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PostureCheckFailureProcessActual) contextValidateOsType(ctx context.Context, formats strfmt.Registry) error {

	if err := m.OsType.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("osType")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PostureCheckFailureProcessActual) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PostureCheckFailureProcessActual) UnmarshalBinary(b []byte) error {
	var res PostureCheckFailureProcessActual
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
