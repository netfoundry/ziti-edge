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

// EnrollmentDetail An enrollment object. Enrolments are tied to identities and portentially a CA. Depending on the
// method, different fields are utilized. For example ottca enrollments use the `ca` field and updb enrollments
// use the username field, but not vice versa.
//
//
// swagger:model enrollmentDetail
type EnrollmentDetail struct {
	BaseEntity

	// details
	// Required: true
	Details map[string]string `json:"details"`

	// edge router
	EdgeRouter *EntityRef `json:"edgeRouter,omitempty"`

	// edge router Id
	EdgeRouterID string `json:"edgeRouterId,omitempty"`

	// expires at
	// Required: true
	// Format: date-time
	ExpiresAt *strfmt.DateTime `json:"expiresAt"`

	// identity
	Identity *EntityRef `json:"identity,omitempty"`

	// identity Id
	IdentityID string `json:"identityId,omitempty"`

	// method
	// Required: true
	Method *string `json:"method"`

	// token
	// Required: true
	Token *string `json:"token"`

	// transit router
	TransitRouter *EntityRef `json:"transitRouter,omitempty"`

	// transit router Id
	TransitRouterID string `json:"transitRouterId,omitempty"`

	// username
	Username string `json:"username,omitempty"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *EnrollmentDetail) UnmarshalJSON(raw []byte) error {
	// AO0
	var aO0 BaseEntity
	if err := swag.ReadJSON(raw, &aO0); err != nil {
		return err
	}
	m.BaseEntity = aO0

	// AO1
	var dataAO1 struct {
		Details map[string]string `json:"details"`

		EdgeRouter *EntityRef `json:"edgeRouter,omitempty"`

		EdgeRouterID string `json:"edgeRouterId,omitempty"`

		ExpiresAt *strfmt.DateTime `json:"expiresAt"`

		Identity *EntityRef `json:"identity,omitempty"`

		IdentityID string `json:"identityId,omitempty"`

		Method *string `json:"method"`

		Token *string `json:"token"`

		TransitRouter *EntityRef `json:"transitRouter,omitempty"`

		TransitRouterID string `json:"transitRouterId,omitempty"`

		Username string `json:"username,omitempty"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.Details = dataAO1.Details

	m.EdgeRouter = dataAO1.EdgeRouter

	m.EdgeRouterID = dataAO1.EdgeRouterID

	m.ExpiresAt = dataAO1.ExpiresAt

	m.Identity = dataAO1.Identity

	m.IdentityID = dataAO1.IdentityID

	m.Method = dataAO1.Method

	m.Token = dataAO1.Token

	m.TransitRouter = dataAO1.TransitRouter

	m.TransitRouterID = dataAO1.TransitRouterID

	m.Username = dataAO1.Username

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m EnrollmentDetail) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	aO0, err := swag.WriteJSON(m.BaseEntity)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, aO0)
	var dataAO1 struct {
		Details map[string]string `json:"details"`

		EdgeRouter *EntityRef `json:"edgeRouter,omitempty"`

		EdgeRouterID string `json:"edgeRouterId,omitempty"`

		ExpiresAt *strfmt.DateTime `json:"expiresAt"`

		Identity *EntityRef `json:"identity,omitempty"`

		IdentityID string `json:"identityId,omitempty"`

		Method *string `json:"method"`

		Token *string `json:"token"`

		TransitRouter *EntityRef `json:"transitRouter,omitempty"`

		TransitRouterID string `json:"transitRouterId,omitempty"`

		Username string `json:"username,omitempty"`
	}

	dataAO1.Details = m.Details

	dataAO1.EdgeRouter = m.EdgeRouter

	dataAO1.EdgeRouterID = m.EdgeRouterID

	dataAO1.ExpiresAt = m.ExpiresAt

	dataAO1.Identity = m.Identity

	dataAO1.IdentityID = m.IdentityID

	dataAO1.Method = m.Method

	dataAO1.Token = m.Token

	dataAO1.TransitRouter = m.TransitRouter

	dataAO1.TransitRouterID = m.TransitRouterID

	dataAO1.Username = m.Username

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this enrollment detail
func (m *EnrollmentDetail) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with BaseEntity
	if err := m.BaseEntity.Validate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDetails(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEdgeRouter(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExpiresAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIdentity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMethod(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateToken(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTransitRouter(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EnrollmentDetail) validateDetails(formats strfmt.Registry) error {

	return nil
}

func (m *EnrollmentDetail) validateEdgeRouter(formats strfmt.Registry) error {

	if swag.IsZero(m.EdgeRouter) { // not required
		return nil
	}

	if m.EdgeRouter != nil {
		if err := m.EdgeRouter.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("edgeRouter")
			}
			return err
		}
	}

	return nil
}

func (m *EnrollmentDetail) validateExpiresAt(formats strfmt.Registry) error {

	if err := validate.Required("expiresAt", "body", m.ExpiresAt); err != nil {
		return err
	}

	if err := validate.FormatOf("expiresAt", "body", "date-time", m.ExpiresAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *EnrollmentDetail) validateIdentity(formats strfmt.Registry) error {

	if swag.IsZero(m.Identity) { // not required
		return nil
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

func (m *EnrollmentDetail) validateMethod(formats strfmt.Registry) error {

	if err := validate.Required("method", "body", m.Method); err != nil {
		return err
	}

	return nil
}

func (m *EnrollmentDetail) validateToken(formats strfmt.Registry) error {

	if err := validate.Required("token", "body", m.Token); err != nil {
		return err
	}

	return nil
}

func (m *EnrollmentDetail) validateTransitRouter(formats strfmt.Registry) error {

	if swag.IsZero(m.TransitRouter) { // not required
		return nil
	}

	if m.TransitRouter != nil {
		if err := m.TransitRouter.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("transitRouter")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *EnrollmentDetail) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EnrollmentDetail) UnmarshalBinary(b []byte) error {
	var res EnrollmentDetail
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}