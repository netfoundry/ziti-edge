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
	"github.com/go-openapi/swag"
)

// NewListTransitRoutersParams creates a new ListTransitRoutersParams object
// with the default values initialized.
func NewListTransitRoutersParams() *ListTransitRoutersParams {
	var ()
	return &ListTransitRoutersParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewListTransitRoutersParamsWithTimeout creates a new ListTransitRoutersParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewListTransitRoutersParamsWithTimeout(timeout time.Duration) *ListTransitRoutersParams {
	var ()
	return &ListTransitRoutersParams{

		timeout: timeout,
	}
}

// NewListTransitRoutersParamsWithContext creates a new ListTransitRoutersParams object
// with the default values initialized, and the ability to set a context for a request
func NewListTransitRoutersParamsWithContext(ctx context.Context) *ListTransitRoutersParams {
	var ()
	return &ListTransitRoutersParams{

		Context: ctx,
	}
}

// NewListTransitRoutersParamsWithHTTPClient creates a new ListTransitRoutersParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewListTransitRoutersParamsWithHTTPClient(client *http.Client) *ListTransitRoutersParams {
	var ()
	return &ListTransitRoutersParams{
		HTTPClient: client,
	}
}

/*ListTransitRoutersParams contains all the parameters to send to the API endpoint
for the list transit routers operation typically these are written to a http.Request
*/
type ListTransitRoutersParams struct {

	/*Filter*/
	Filter *string
	/*Limit*/
	Limit *int64
	/*Offset*/
	Offset *int64

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the list transit routers params
func (o *ListTransitRoutersParams) WithTimeout(timeout time.Duration) *ListTransitRoutersParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list transit routers params
func (o *ListTransitRoutersParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list transit routers params
func (o *ListTransitRoutersParams) WithContext(ctx context.Context) *ListTransitRoutersParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list transit routers params
func (o *ListTransitRoutersParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list transit routers params
func (o *ListTransitRoutersParams) WithHTTPClient(client *http.Client) *ListTransitRoutersParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list transit routers params
func (o *ListTransitRoutersParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the list transit routers params
func (o *ListTransitRoutersParams) WithFilter(filter *string) *ListTransitRoutersParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the list transit routers params
func (o *ListTransitRoutersParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the list transit routers params
func (o *ListTransitRoutersParams) WithLimit(limit *int64) *ListTransitRoutersParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the list transit routers params
func (o *ListTransitRoutersParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the list transit routers params
func (o *ListTransitRoutersParams) WithOffset(offset *int64) *ListTransitRoutersParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the list transit routers params
func (o *ListTransitRoutersParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WriteToRequest writes these params to a swagger request
func (o *ListTransitRoutersParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Filter != nil {

		// query param filter
		var qrFilter string
		if o.Filter != nil {
			qrFilter = *o.Filter
		}
		qFilter := qrFilter
		if qFilter != "" {
			if err := r.SetQueryParam("filter", qFilter); err != nil {
				return err
			}
		}

	}

	if o.Limit != nil {

		// query param limit
		var qrLimit int64
		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := swag.FormatInt64(qrLimit)
		if qLimit != "" {
			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}

	}

	if o.Offset != nil {

		// query param offset
		var qrOffset int64
		if o.Offset != nil {
			qrOffset = *o.Offset
		}
		qOffset := swag.FormatInt64(qrOffset)
		if qOffset != "" {
			if err := r.SetQueryParam("offset", qOffset); err != nil {
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
