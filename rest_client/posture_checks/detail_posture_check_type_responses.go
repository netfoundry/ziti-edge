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

package posture_checks

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// DetailPostureCheckTypeReader is a Reader for the DetailPostureCheckType structure.
type DetailPostureCheckTypeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DetailPostureCheckTypeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDetailPostureCheckTypeOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDetailPostureCheckTypeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDetailPostureCheckTypeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDetailPostureCheckTypeOK creates a DetailPostureCheckTypeOK with default headers values
func NewDetailPostureCheckTypeOK() *DetailPostureCheckTypeOK {
	return &DetailPostureCheckTypeOK{}
}

/*DetailPostureCheckTypeOK handles this case with default header values.

Retrieves a singular posture check type by id
*/
type DetailPostureCheckTypeOK struct {
	Payload *rest_model.DetailPostureCheckTypeEnvelope
}

func (o *DetailPostureCheckTypeOK) Error() string {
	return fmt.Sprintf("[GET /posture-check-types/{id}][%d] detailPostureCheckTypeOK  %+v", 200, o.Payload)
}

func (o *DetailPostureCheckTypeOK) GetPayload() *rest_model.DetailPostureCheckTypeEnvelope {
	return o.Payload
}

func (o *DetailPostureCheckTypeOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.DetailPostureCheckTypeEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailPostureCheckTypeUnauthorized creates a DetailPostureCheckTypeUnauthorized with default headers values
func NewDetailPostureCheckTypeUnauthorized() *DetailPostureCheckTypeUnauthorized {
	return &DetailPostureCheckTypeUnauthorized{}
}

/*DetailPostureCheckTypeUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type DetailPostureCheckTypeUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailPostureCheckTypeUnauthorized) Error() string {
	return fmt.Sprintf("[GET /posture-check-types/{id}][%d] detailPostureCheckTypeUnauthorized  %+v", 401, o.Payload)
}

func (o *DetailPostureCheckTypeUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailPostureCheckTypeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailPostureCheckTypeNotFound creates a DetailPostureCheckTypeNotFound with default headers values
func NewDetailPostureCheckTypeNotFound() *DetailPostureCheckTypeNotFound {
	return &DetailPostureCheckTypeNotFound{}
}

/*DetailPostureCheckTypeNotFound handles this case with default header values.

The requested resource does not exist
*/
type DetailPostureCheckTypeNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailPostureCheckTypeNotFound) Error() string {
	return fmt.Sprintf("[GET /posture-check-types/{id}][%d] detailPostureCheckTypeNotFound  %+v", 404, o.Payload)
}

func (o *DetailPostureCheckTypeNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailPostureCheckTypeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}