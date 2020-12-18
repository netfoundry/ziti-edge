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

package current_api_session

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

// NewListCurrentAPISessionCertificatesParams creates a new ListCurrentAPISessionCertificatesParams object
// with the default values initialized.
func NewListCurrentAPISessionCertificatesParams() *ListCurrentAPISessionCertificatesParams {
	var ()
	return &ListCurrentAPISessionCertificatesParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewListCurrentAPISessionCertificatesParamsWithTimeout creates a new ListCurrentAPISessionCertificatesParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewListCurrentAPISessionCertificatesParamsWithTimeout(timeout time.Duration) *ListCurrentAPISessionCertificatesParams {
	var ()
	return &ListCurrentAPISessionCertificatesParams{

		timeout: timeout,
	}
}

// NewListCurrentAPISessionCertificatesParamsWithContext creates a new ListCurrentAPISessionCertificatesParams object
// with the default values initialized, and the ability to set a context for a request
func NewListCurrentAPISessionCertificatesParamsWithContext(ctx context.Context) *ListCurrentAPISessionCertificatesParams {
	var ()
	return &ListCurrentAPISessionCertificatesParams{

		Context: ctx,
	}
}

// NewListCurrentAPISessionCertificatesParamsWithHTTPClient creates a new ListCurrentAPISessionCertificatesParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewListCurrentAPISessionCertificatesParamsWithHTTPClient(client *http.Client) *ListCurrentAPISessionCertificatesParams {
	var ()
	return &ListCurrentAPISessionCertificatesParams{
		HTTPClient: client,
	}
}

/*ListCurrentAPISessionCertificatesParams contains all the parameters to send to the API endpoint
for the list current Api session certificates operation typically these are written to a http.Request
*/
type ListCurrentAPISessionCertificatesParams struct {

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

// WithTimeout adds the timeout to the list current Api session certificates params
func (o *ListCurrentAPISessionCertificatesParams) WithTimeout(timeout time.Duration) *ListCurrentAPISessionCertificatesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list current Api session certificates params
func (o *ListCurrentAPISessionCertificatesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list current Api session certificates params
func (o *ListCurrentAPISessionCertificatesParams) WithContext(ctx context.Context) *ListCurrentAPISessionCertificatesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list current Api session certificates params
func (o *ListCurrentAPISessionCertificatesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list current Api session certificates params
func (o *ListCurrentAPISessionCertificatesParams) WithHTTPClient(client *http.Client) *ListCurrentAPISessionCertificatesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list current Api session certificates params
func (o *ListCurrentAPISessionCertificatesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the list current Api session certificates params
func (o *ListCurrentAPISessionCertificatesParams) WithFilter(filter *string) *ListCurrentAPISessionCertificatesParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the list current Api session certificates params
func (o *ListCurrentAPISessionCertificatesParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithLimit adds the limit to the list current Api session certificates params
func (o *ListCurrentAPISessionCertificatesParams) WithLimit(limit *int64) *ListCurrentAPISessionCertificatesParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the list current Api session certificates params
func (o *ListCurrentAPISessionCertificatesParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOffset adds the offset to the list current Api session certificates params
func (o *ListCurrentAPISessionCertificatesParams) WithOffset(offset *int64) *ListCurrentAPISessionCertificatesParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the list current Api session certificates params
func (o *ListCurrentAPISessionCertificatesParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WriteToRequest writes these params to a swagger request
func (o *ListCurrentAPISessionCertificatesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
