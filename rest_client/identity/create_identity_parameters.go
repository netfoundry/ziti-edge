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

// NewCreateIdentityParams creates a new CreateIdentityParams object
// with the default values initialized.
func NewCreateIdentityParams() *CreateIdentityParams {
	var ()
	return &CreateIdentityParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewCreateIdentityParamsWithTimeout creates a new CreateIdentityParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewCreateIdentityParamsWithTimeout(timeout time.Duration) *CreateIdentityParams {
	var ()
	return &CreateIdentityParams{

		timeout: timeout,
	}
}

// NewCreateIdentityParamsWithContext creates a new CreateIdentityParams object
// with the default values initialized, and the ability to set a context for a request
func NewCreateIdentityParamsWithContext(ctx context.Context) *CreateIdentityParams {
	var ()
	return &CreateIdentityParams{

		Context: ctx,
	}
}

// NewCreateIdentityParamsWithHTTPClient creates a new CreateIdentityParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewCreateIdentityParamsWithHTTPClient(client *http.Client) *CreateIdentityParams {
	var ()
	return &CreateIdentityParams{
		HTTPClient: client,
	}
}

/*CreateIdentityParams contains all the parameters to send to the API endpoint
for the create identity operation typically these are written to a http.Request
*/
type CreateIdentityParams struct {

	/*Body
	  An identity to create

	*/
	Body *rest_model.IdentityCreate

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the create identity params
func (o *CreateIdentityParams) WithTimeout(timeout time.Duration) *CreateIdentityParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create identity params
func (o *CreateIdentityParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create identity params
func (o *CreateIdentityParams) WithContext(ctx context.Context) *CreateIdentityParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create identity params
func (o *CreateIdentityParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create identity params
func (o *CreateIdentityParams) WithHTTPClient(client *http.Client) *CreateIdentityParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create identity params
func (o *CreateIdentityParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the create identity params
func (o *CreateIdentityParams) WithBody(body *rest_model.IdentityCreate) *CreateIdentityParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the create identity params
func (o *CreateIdentityParams) SetBody(body *rest_model.IdentityCreate) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *CreateIdentityParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
