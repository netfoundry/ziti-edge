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

// IdentityCreate An identity to create
//
// swagger:model identityCreate
type IdentityCreate struct {

	// app data
	AppData Tags `json:"appData"`

	// default hosting cost
	DefaultHostingCost *TerminatorCost `json:"defaultHostingCost,omitempty"`

	// default hosting precedence
	DefaultHostingPrecedence TerminatorPrecedence `json:"defaultHostingPrecedence,omitempty"`

	// enrollment
	Enrollment *IdentityCreateEnrollment `json:"enrollment,omitempty"`

	// is admin
	// Required: true
	IsAdmin *bool `json:"isAdmin"`

	// name
	// Required: true
	Name *string `json:"name"`

	// role attributes
	RoleAttributes Attributes `json:"roleAttributes"`

	// service hosting costs
	ServiceHostingCosts TerminatorCostMap `json:"serviceHostingCosts,omitempty"`

	// service hosting precedences
	ServiceHostingPrecedences TerminatorPrecedenceMap `json:"serviceHostingPrecedences,omitempty"`

	// tags
	Tags Tags `json:"tags"`

	// type
	// Required: true
	Type *IdentityType `json:"type"`
}

// Validate validates this identity create
func (m *IdentityCreate) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAppData(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDefaultHostingCost(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDefaultHostingPrecedence(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEnrollment(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsAdmin(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRoleAttributes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServiceHostingCosts(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServiceHostingPrecedences(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTags(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IdentityCreate) validateAppData(formats strfmt.Registry) error {
	if swag.IsZero(m.AppData) { // not required
		return nil
	}

	if m.AppData != nil {
		if err := m.AppData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("appData")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityCreate) validateDefaultHostingCost(formats strfmt.Registry) error {
	if swag.IsZero(m.DefaultHostingCost) { // not required
		return nil
	}

	if m.DefaultHostingCost != nil {
		if err := m.DefaultHostingCost.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("defaultHostingCost")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityCreate) validateDefaultHostingPrecedence(formats strfmt.Registry) error {
	if swag.IsZero(m.DefaultHostingPrecedence) { // not required
		return nil
	}

	if err := m.DefaultHostingPrecedence.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("defaultHostingPrecedence")
		}
		return err
	}

	return nil
}

func (m *IdentityCreate) validateEnrollment(formats strfmt.Registry) error {
	if swag.IsZero(m.Enrollment) { // not required
		return nil
	}

	if m.Enrollment != nil {
		if err := m.Enrollment.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("enrollment")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityCreate) validateIsAdmin(formats strfmt.Registry) error {

	if err := validate.Required("isAdmin", "body", m.IsAdmin); err != nil {
		return err
	}

	return nil
}

func (m *IdentityCreate) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *IdentityCreate) validateRoleAttributes(formats strfmt.Registry) error {
	if swag.IsZero(m.RoleAttributes) { // not required
		return nil
	}

	if err := m.RoleAttributes.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("roleAttributes")
		}
		return err
	}

	return nil
}

func (m *IdentityCreate) validateServiceHostingCosts(formats strfmt.Registry) error {
	if swag.IsZero(m.ServiceHostingCosts) { // not required
		return nil
	}

	if m.ServiceHostingCosts != nil {
		if err := m.ServiceHostingCosts.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("serviceHostingCosts")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityCreate) validateServiceHostingPrecedences(formats strfmt.Registry) error {
	if swag.IsZero(m.ServiceHostingPrecedences) { // not required
		return nil
	}

	if m.ServiceHostingPrecedences != nil {
		if err := m.ServiceHostingPrecedences.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("serviceHostingPrecedences")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityCreate) validateTags(formats strfmt.Registry) error {
	if swag.IsZero(m.Tags) { // not required
		return nil
	}

	if m.Tags != nil {
		if err := m.Tags.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("tags")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityCreate) validateType(formats strfmt.Registry) error {

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	if m.Type != nil {
		if err := m.Type.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("type")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this identity create based on the context it is used
func (m *IdentityCreate) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAppData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDefaultHostingCost(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDefaultHostingPrecedence(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateEnrollment(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRoleAttributes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateServiceHostingCosts(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateServiceHostingPrecedences(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTags(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IdentityCreate) contextValidateAppData(ctx context.Context, formats strfmt.Registry) error {

	if err := m.AppData.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("appData")
		}
		return err
	}

	return nil
}

func (m *IdentityCreate) contextValidateDefaultHostingCost(ctx context.Context, formats strfmt.Registry) error {

	if m.DefaultHostingCost != nil {
		if err := m.DefaultHostingCost.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("defaultHostingCost")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityCreate) contextValidateDefaultHostingPrecedence(ctx context.Context, formats strfmt.Registry) error {

	if err := m.DefaultHostingPrecedence.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("defaultHostingPrecedence")
		}
		return err
	}

	return nil
}

func (m *IdentityCreate) contextValidateEnrollment(ctx context.Context, formats strfmt.Registry) error {

	if m.Enrollment != nil {
		if err := m.Enrollment.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("enrollment")
			}
			return err
		}
	}

	return nil
}

func (m *IdentityCreate) contextValidateRoleAttributes(ctx context.Context, formats strfmt.Registry) error {

	if err := m.RoleAttributes.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("roleAttributes")
		}
		return err
	}

	return nil
}

func (m *IdentityCreate) contextValidateServiceHostingCosts(ctx context.Context, formats strfmt.Registry) error {

	if err := m.ServiceHostingCosts.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("serviceHostingCosts")
		}
		return err
	}

	return nil
}

func (m *IdentityCreate) contextValidateServiceHostingPrecedences(ctx context.Context, formats strfmt.Registry) error {

	if err := m.ServiceHostingPrecedences.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("serviceHostingPrecedences")
		}
		return err
	}

	return nil
}

func (m *IdentityCreate) contextValidateTags(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Tags.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("tags")
		}
		return err
	}

	return nil
}

func (m *IdentityCreate) contextValidateType(ctx context.Context, formats strfmt.Registry) error {

	if m.Type != nil {
		if err := m.Type.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("type")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *IdentityCreate) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IdentityCreate) UnmarshalBinary(b []byte) error {
	var res IdentityCreate
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// IdentityCreateEnrollment identity create enrollment
//
// swagger:model IdentityCreateEnrollment
type IdentityCreateEnrollment struct {

	// ott
	Ott bool `json:"ott,omitempty"`

	// ottca
	Ottca string `json:"ottca,omitempty"`

	// updb
	Updb string `json:"updb,omitempty"`
}

// Validate validates this identity create enrollment
func (m *IdentityCreateEnrollment) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this identity create enrollment based on context it is used
func (m *IdentityCreateEnrollment) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *IdentityCreateEnrollment) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IdentityCreateEnrollment) UnmarshalBinary(b []byte) error {
	var res IdentityCreateEnrollment
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
