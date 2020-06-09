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

package identity

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

// NewDisassociateIdentitysServiceConfigsParams creates a new DisassociateIdentitysServiceConfigsParams object
// with the default values initialized.
func NewDisassociateIdentitysServiceConfigsParams() *DisassociateIdentitysServiceConfigsParams {
	var ()
	return &DisassociateIdentitysServiceConfigsParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewDisassociateIdentitysServiceConfigsParamsWithTimeout creates a new DisassociateIdentitysServiceConfigsParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewDisassociateIdentitysServiceConfigsParamsWithTimeout(timeout time.Duration) *DisassociateIdentitysServiceConfigsParams {
	var ()
	return &DisassociateIdentitysServiceConfigsParams{

		timeout: timeout,
	}
}

// NewDisassociateIdentitysServiceConfigsParamsWithContext creates a new DisassociateIdentitysServiceConfigsParams object
// with the default values initialized, and the ability to set a context for a request
func NewDisassociateIdentitysServiceConfigsParamsWithContext(ctx context.Context) *DisassociateIdentitysServiceConfigsParams {
	var ()
	return &DisassociateIdentitysServiceConfigsParams{

		Context: ctx,
	}
}

// NewDisassociateIdentitysServiceConfigsParamsWithHTTPClient creates a new DisassociateIdentitysServiceConfigsParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewDisassociateIdentitysServiceConfigsParamsWithHTTPClient(client *http.Client) *DisassociateIdentitysServiceConfigsParams {
	var ()
	return &DisassociateIdentitysServiceConfigsParams{
		HTTPClient: client,
	}
}

/*DisassociateIdentitysServiceConfigsParams contains all the parameters to send to the API endpoint
for the disassociate identitys service configs operation typically these are written to a http.Request
*/
type DisassociateIdentitysServiceConfigsParams struct {

	/*Body
	  An array of service and config id pairs to remove

	*/
	Body rest_model.ServiceConfigsAssignList
	/*ID
	  The id of the requested resource

	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the disassociate identitys service configs params
func (o *DisassociateIdentitysServiceConfigsParams) WithTimeout(timeout time.Duration) *DisassociateIdentitysServiceConfigsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the disassociate identitys service configs params
func (o *DisassociateIdentitysServiceConfigsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the disassociate identitys service configs params
func (o *DisassociateIdentitysServiceConfigsParams) WithContext(ctx context.Context) *DisassociateIdentitysServiceConfigsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the disassociate identitys service configs params
func (o *DisassociateIdentitysServiceConfigsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the disassociate identitys service configs params
func (o *DisassociateIdentitysServiceConfigsParams) WithHTTPClient(client *http.Client) *DisassociateIdentitysServiceConfigsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the disassociate identitys service configs params
func (o *DisassociateIdentitysServiceConfigsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the disassociate identitys service configs params
func (o *DisassociateIdentitysServiceConfigsParams) WithBody(body rest_model.ServiceConfigsAssignList) *DisassociateIdentitysServiceConfigsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the disassociate identitys service configs params
func (o *DisassociateIdentitysServiceConfigsParams) SetBody(body rest_model.ServiceConfigsAssignList) {
	o.Body = body
}

// WithID adds the id to the disassociate identitys service configs params
func (o *DisassociateIdentitysServiceConfigsParams) WithID(id string) *DisassociateIdentitysServiceConfigsParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the disassociate identitys service configs params
func (o *DisassociateIdentitysServiceConfigsParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *DisassociateIdentitysServiceConfigsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
