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

package service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// ListServicesReader is a Reader for the ListServices structure.
type ListServicesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListServicesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListServicesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListServicesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewListServicesOK creates a ListServicesOK with default headers values
func NewListServicesOK() *ListServicesOK {
	return &ListServicesOK{}
}

/*ListServicesOK handles this case with default header values.

A list of services
*/
type ListServicesOK struct {
	Payload *rest_model.ListServicesEnvelope
}

func (o *ListServicesOK) Error() string {
	return fmt.Sprintf("[GET /services][%d] listServicesOK  %+v", 200, o.Payload)
}

func (o *ListServicesOK) GetPayload() *rest_model.ListServicesEnvelope {
	return o.Payload
}

func (o *ListServicesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.ListServicesEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListServicesUnauthorized creates a ListServicesUnauthorized with default headers values
func NewListServicesUnauthorized() *ListServicesUnauthorized {
	return &ListServicesUnauthorized{}
}

/*ListServicesUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type ListServicesUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ListServicesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /services][%d] listServicesUnauthorized  %+v", 401, o.Payload)
}

func (o *ListServicesUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ListServicesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
