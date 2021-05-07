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

package enroll

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// ExtendRouterEnrollmentReader is a Reader for the ExtendRouterEnrollment structure.
type ExtendRouterEnrollmentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ExtendRouterEnrollmentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewExtendRouterEnrollmentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewExtendRouterEnrollmentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewExtendRouterEnrollmentOK creates a ExtendRouterEnrollmentOK with default headers values
func NewExtendRouterEnrollmentOK() *ExtendRouterEnrollmentOK {
	return &ExtendRouterEnrollmentOK{}
}

/* ExtendRouterEnrollmentOK describes a response with status code 200, with default header values.

A response containg the edge routers new signed certificates (server chain, server cert, CAs).
*/
type ExtendRouterEnrollmentOK struct {
	Payload *rest_model.EnrollmentCertsEnvelope
}

func (o *ExtendRouterEnrollmentOK) Error() string {
	return fmt.Sprintf("[POST /enroll/extend/router][%d] extendRouterEnrollmentOK  %+v", 200, o.Payload)
}
func (o *ExtendRouterEnrollmentOK) GetPayload() *rest_model.EnrollmentCertsEnvelope {
	return o.Payload
}

func (o *ExtendRouterEnrollmentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.EnrollmentCertsEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewExtendRouterEnrollmentUnauthorized creates a ExtendRouterEnrollmentUnauthorized with default headers values
func NewExtendRouterEnrollmentUnauthorized() *ExtendRouterEnrollmentUnauthorized {
	return &ExtendRouterEnrollmentUnauthorized{}
}

/* ExtendRouterEnrollmentUnauthorized describes a response with status code 401, with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type ExtendRouterEnrollmentUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ExtendRouterEnrollmentUnauthorized) Error() string {
	return fmt.Sprintf("[POST /enroll/extend/router][%d] extendRouterEnrollmentUnauthorized  %+v", 401, o.Payload)
}
func (o *ExtendRouterEnrollmentUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ExtendRouterEnrollmentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
