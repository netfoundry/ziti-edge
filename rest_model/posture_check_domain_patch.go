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
	"bytes"
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// PostureCheckDomainPatch posture check domain patch
//
// swagger:model postureCheckDomainPatch
type PostureCheckDomainPatch struct {
	nameField string

	roleAttributesField Attributes

	tagsField Tags

	// domains
	// Min Items: 1
	Domains []string `json:"domains"`
}

// Name gets the name of this subtype
func (m *PostureCheckDomainPatch) Name() string {
	return m.nameField
}

// SetName sets the name of this subtype
func (m *PostureCheckDomainPatch) SetName(val string) {
	m.nameField = val
}

// RoleAttributes gets the role attributes of this subtype
func (m *PostureCheckDomainPatch) RoleAttributes() Attributes {
	return m.roleAttributesField
}

// SetRoleAttributes sets the role attributes of this subtype
func (m *PostureCheckDomainPatch) SetRoleAttributes(val Attributes) {
	m.roleAttributesField = val
}

// Tags gets the tags of this subtype
func (m *PostureCheckDomainPatch) Tags() Tags {
	return m.tagsField
}

// SetTags sets the tags of this subtype
func (m *PostureCheckDomainPatch) SetTags(val Tags) {
	m.tagsField = val
}

// UnmarshalJSON unmarshals this object with a polymorphic type from a JSON structure
func (m *PostureCheckDomainPatch) UnmarshalJSON(raw []byte) error {
	var data struct {

		// domains
		// Min Items: 1
		Domains []string `json:"domains"`
	}
	buf := bytes.NewBuffer(raw)
	dec := json.NewDecoder(buf)
	dec.UseNumber()

	if err := dec.Decode(&data); err != nil {
		return err
	}

	var base struct {
		/* Just the base type fields. Used for unmashalling polymorphic types.*/

		Name string `json:"name,omitempty"`

		RoleAttributes Attributes `json:"roleAttributes"`

		Tags Tags `json:"tags"`
	}
	buf = bytes.NewBuffer(raw)
	dec = json.NewDecoder(buf)
	dec.UseNumber()

	if err := dec.Decode(&base); err != nil {
		return err
	}

	var result PostureCheckDomainPatch

	result.nameField = base.Name

	result.roleAttributesField = base.RoleAttributes

	result.tagsField = base.Tags

	result.Domains = data.Domains

	*m = result

	return nil
}

// MarshalJSON marshals this object with a polymorphic type to a JSON structure
func (m PostureCheckDomainPatch) MarshalJSON() ([]byte, error) {
	var b1, b2, b3 []byte
	var err error
	b1, err = json.Marshal(struct {

		// domains
		// Min Items: 1
		Domains []string `json:"domains"`
	}{

		Domains: m.Domains,
	})
	if err != nil {
		return nil, err
	}
	b2, err = json.Marshal(struct {
		Name string `json:"name,omitempty"`

		RoleAttributes Attributes `json:"roleAttributes"`

		Tags Tags `json:"tags"`
	}{

		Name: m.Name(),

		RoleAttributes: m.RoleAttributes(),

		Tags: m.Tags(),
	})
	if err != nil {
		return nil, err
	}

	return swag.ConcatJSON(b1, b2, b3), nil
}

// Validate validates this posture check domain patch
func (m *PostureCheckDomainPatch) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRoleAttributes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTags(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDomains(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PostureCheckDomainPatch) validateRoleAttributes(formats strfmt.Registry) error {

	if swag.IsZero(m.RoleAttributes()) { // not required
		return nil
	}

	if err := m.RoleAttributes().Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("roleAttributes")
		}
		return err
	}

	return nil
}

func (m *PostureCheckDomainPatch) validateTags(formats strfmt.Registry) error {

	if swag.IsZero(m.Tags()) { // not required
		return nil
	}

	if m.Tags() != nil {
		if err := m.Tags().Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("tags")
			}
			return err
		}
	}

	return nil
}

func (m *PostureCheckDomainPatch) validateDomains(formats strfmt.Registry) error {

	if swag.IsZero(m.Domains) { // not required
		return nil
	}

	iDomainsSize := int64(len(m.Domains))

	if err := validate.MinItems("domains", "body", iDomainsSize, 1); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this posture check domain patch based on the context it is used
func (m *PostureCheckDomainPatch) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRoleAttributes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTags(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PostureCheckDomainPatch) contextValidateRoleAttributes(ctx context.Context, formats strfmt.Registry) error {

	if err := m.RoleAttributes().ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("roleAttributes")
		}
		return err
	}

	return nil
}

func (m *PostureCheckDomainPatch) contextValidateTags(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Tags().ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("tags")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PostureCheckDomainPatch) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PostureCheckDomainPatch) UnmarshalBinary(b []byte) error {
	var res PostureCheckDomainPatch
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
