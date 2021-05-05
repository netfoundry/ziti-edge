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

package config

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// UpdateConfigTypeReader is a Reader for the UpdateConfigType structure.
type UpdateConfigTypeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateConfigTypeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateConfigTypeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateConfigTypeBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateConfigTypeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateConfigTypeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewUpdateConfigTypeOK creates a UpdateConfigTypeOK with default headers values
func NewUpdateConfigTypeOK() *UpdateConfigTypeOK {
	return &UpdateConfigTypeOK{}
}

/* UpdateConfigTypeOK describes a response with status code 200, with default header values.

The update request was successful and the resource has been altered
*/
type UpdateConfigTypeOK struct {
	Payload *rest_model.Empty
}

func (o *UpdateConfigTypeOK) Error() string {
	return fmt.Sprintf("[PUT /config-types/{id}][%d] updateConfigTypeOK  %+v", 200, o.Payload)
}
func (o *UpdateConfigTypeOK) GetPayload() *rest_model.Empty {
	return o.Payload
}

func (o *UpdateConfigTypeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.Empty)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateConfigTypeBadRequest creates a UpdateConfigTypeBadRequest with default headers values
func NewUpdateConfigTypeBadRequest() *UpdateConfigTypeBadRequest {
	return &UpdateConfigTypeBadRequest{}
}

/* UpdateConfigTypeBadRequest describes a response with status code 400, with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type UpdateConfigTypeBadRequest struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *UpdateConfigTypeBadRequest) Error() string {
	return fmt.Sprintf("[PUT /config-types/{id}][%d] updateConfigTypeBadRequest  %+v", 400, o.Payload)
}
func (o *UpdateConfigTypeBadRequest) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *UpdateConfigTypeBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateConfigTypeUnauthorized creates a UpdateConfigTypeUnauthorized with default headers values
func NewUpdateConfigTypeUnauthorized() *UpdateConfigTypeUnauthorized {
	return &UpdateConfigTypeUnauthorized{}
}

/* UpdateConfigTypeUnauthorized describes a response with status code 401, with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type UpdateConfigTypeUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *UpdateConfigTypeUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /config-types/{id}][%d] updateConfigTypeUnauthorized  %+v", 401, o.Payload)
}
func (o *UpdateConfigTypeUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *UpdateConfigTypeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateConfigTypeNotFound creates a UpdateConfigTypeNotFound with default headers values
func NewUpdateConfigTypeNotFound() *UpdateConfigTypeNotFound {
	return &UpdateConfigTypeNotFound{}
}

/* UpdateConfigTypeNotFound describes a response with status code 404, with default header values.

The requested resource does not exist
*/
type UpdateConfigTypeNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *UpdateConfigTypeNotFound) Error() string {
	return fmt.Sprintf("[PUT /config-types/{id}][%d] updateConfigTypeNotFound  %+v", 404, o.Payload)
}
func (o *UpdateConfigTypeNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *UpdateConfigTypeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}