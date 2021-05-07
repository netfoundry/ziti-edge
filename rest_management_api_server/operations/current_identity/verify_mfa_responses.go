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

package current_identity

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// VerifyMfaOKCode is the HTTP code returned for type VerifyMfaOK
const VerifyMfaOKCode int = 200

/*VerifyMfaOK Base empty response

swagger:response verifyMfaOK
*/
type VerifyMfaOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.Empty `json:"body,omitempty"`
}

// NewVerifyMfaOK creates VerifyMfaOK with default headers values
func NewVerifyMfaOK() *VerifyMfaOK {

	return &VerifyMfaOK{}
}

// WithPayload adds the payload to the verify mfa o k response
func (o *VerifyMfaOK) WithPayload(payload *rest_model.Empty) *VerifyMfaOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the verify mfa o k response
func (o *VerifyMfaOK) SetPayload(payload *rest_model.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *VerifyMfaOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// VerifyMfaUnauthorizedCode is the HTTP code returned for type VerifyMfaUnauthorized
const VerifyMfaUnauthorizedCode int = 401

/*VerifyMfaUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response verifyMfaUnauthorized
*/
type VerifyMfaUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewVerifyMfaUnauthorized creates VerifyMfaUnauthorized with default headers values
func NewVerifyMfaUnauthorized() *VerifyMfaUnauthorized {

	return &VerifyMfaUnauthorized{}
}

// WithPayload adds the payload to the verify mfa unauthorized response
func (o *VerifyMfaUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *VerifyMfaUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the verify mfa unauthorized response
func (o *VerifyMfaUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *VerifyMfaUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// VerifyMfaNotFoundCode is the HTTP code returned for type VerifyMfaNotFound
const VerifyMfaNotFoundCode int = 404

/*VerifyMfaNotFound The requested resource does not exist

swagger:response verifyMfaNotFound
*/
type VerifyMfaNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewVerifyMfaNotFound creates VerifyMfaNotFound with default headers values
func NewVerifyMfaNotFound() *VerifyMfaNotFound {

	return &VerifyMfaNotFound{}
}

// WithPayload adds the payload to the verify mfa not found response
func (o *VerifyMfaNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *VerifyMfaNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the verify mfa not found response
func (o *VerifyMfaNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *VerifyMfaNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
