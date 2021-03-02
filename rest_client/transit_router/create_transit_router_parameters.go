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

package transit_router

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

// NewCreateTransitRouterParams creates a new CreateTransitRouterParams object
// with the default values initialized.
func NewCreateTransitRouterParams() *CreateTransitRouterParams {
	var ()
	return &CreateTransitRouterParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewCreateTransitRouterParamsWithTimeout creates a new CreateTransitRouterParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewCreateTransitRouterParamsWithTimeout(timeout time.Duration) *CreateTransitRouterParams {
	var ()
	return &CreateTransitRouterParams{

		timeout: timeout,
	}
}

// NewCreateTransitRouterParamsWithContext creates a new CreateTransitRouterParams object
// with the default values initialized, and the ability to set a context for a request
func NewCreateTransitRouterParamsWithContext(ctx context.Context) *CreateTransitRouterParams {
	var ()
	return &CreateTransitRouterParams{

		Context: ctx,
	}
}

// NewCreateTransitRouterParamsWithHTTPClient creates a new CreateTransitRouterParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewCreateTransitRouterParamsWithHTTPClient(client *http.Client) *CreateTransitRouterParams {
	var ()
	return &CreateTransitRouterParams{
		HTTPClient: client,
	}
}

/*CreateTransitRouterParams contains all the parameters to send to the API endpoint
for the create transit router operation typically these are written to a http.Request
*/
type CreateTransitRouterParams struct {

	/*Router
	  A transit router to create

	*/
	Router *rest_model.TransitRouterCreate

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the create transit router params
func (o *CreateTransitRouterParams) WithTimeout(timeout time.Duration) *CreateTransitRouterParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create transit router params
func (o *CreateTransitRouterParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create transit router params
func (o *CreateTransitRouterParams) WithContext(ctx context.Context) *CreateTransitRouterParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create transit router params
func (o *CreateTransitRouterParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create transit router params
func (o *CreateTransitRouterParams) WithHTTPClient(client *http.Client) *CreateTransitRouterParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create transit router params
func (o *CreateTransitRouterParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRouter adds the router to the create transit router params
func (o *CreateTransitRouterParams) WithRouter(router *rest_model.TransitRouterCreate) *CreateTransitRouterParams {
	o.SetRouter(router)
	return o
}

// SetRouter adds the router to the create transit router params
func (o *CreateTransitRouterParams) SetRouter(router *rest_model.TransitRouterCreate) {
	o.Router = router
}

// WriteToRequest writes these params to a swagger request
func (o *CreateTransitRouterParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Router != nil {
		if err := r.SetBodyParam(o.Router); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
