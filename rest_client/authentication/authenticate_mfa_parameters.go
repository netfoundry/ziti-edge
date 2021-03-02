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

package authentication

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// NewAuthenticateMfaParams creates a new AuthenticateMfaParams object
// with the default values initialized.
func NewAuthenticateMfaParams() *AuthenticateMfaParams {
	var ()
	return &AuthenticateMfaParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewAuthenticateMfaParamsWithTimeout creates a new AuthenticateMfaParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewAuthenticateMfaParamsWithTimeout(timeout time.Duration) *AuthenticateMfaParams {
	var ()
	return &AuthenticateMfaParams{

		timeout: timeout,
	}
}

// NewAuthenticateMfaParamsWithContext creates a new AuthenticateMfaParams object
// with the default values initialized, and the ability to set a context for a request
func NewAuthenticateMfaParamsWithContext(ctx context.Context) *AuthenticateMfaParams {
	var ()
	return &AuthenticateMfaParams{

		Context: ctx,
	}
}

// NewAuthenticateMfaParamsWithHTTPClient creates a new AuthenticateMfaParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewAuthenticateMfaParamsWithHTTPClient(client *http.Client) *AuthenticateMfaParams {
	var ()
	return &AuthenticateMfaParams{
		HTTPClient: client,
	}
}

/*AuthenticateMfaParams contains all the parameters to send to the API endpoint
for the authenticate mfa operation typically these are written to a http.Request
*/
type AuthenticateMfaParams struct {

	/*MfaAuth
	  An MFA validation request

	*/
	MfaAuth *rest_model.MfaCode

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the authenticate mfa params
func (o *AuthenticateMfaParams) WithTimeout(timeout time.Duration) *AuthenticateMfaParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the authenticate mfa params
func (o *AuthenticateMfaParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the authenticate mfa params
func (o *AuthenticateMfaParams) WithContext(ctx context.Context) *AuthenticateMfaParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the authenticate mfa params
func (o *AuthenticateMfaParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the authenticate mfa params
func (o *AuthenticateMfaParams) WithHTTPClient(client *http.Client) *AuthenticateMfaParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the authenticate mfa params
func (o *AuthenticateMfaParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithMfaAuth adds the mfaAuth to the authenticate mfa params
func (o *AuthenticateMfaParams) WithMfaAuth(mfaAuth *rest_model.MfaCode) *AuthenticateMfaParams {
	o.SetMfaAuth(mfaAuth)
	return o
}

// SetMfaAuth adds the mfaAuth to the authenticate mfa params
func (o *AuthenticateMfaParams) SetMfaAuth(mfaAuth *rest_model.MfaCode) {
	o.MfaAuth = mfaAuth
}

// WriteToRequest writes these params to a swagger request
func (o *AuthenticateMfaParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.MfaAuth != nil {
		if err := r.SetBodyParam(o.MfaAuth); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
