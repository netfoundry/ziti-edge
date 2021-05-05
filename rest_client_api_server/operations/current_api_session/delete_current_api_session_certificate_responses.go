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
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// DeleteCurrentAPISessionCertificateOKCode is the HTTP code returned for type DeleteCurrentAPISessionCertificateOK
const DeleteCurrentAPISessionCertificateOKCode int = 200

/*DeleteCurrentAPISessionCertificateOK The delete request was successful and the resource has been removed

swagger:response deleteCurrentApiSessionCertificateOK
*/
type DeleteCurrentAPISessionCertificateOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.Empty `json:"body,omitempty"`
}

// NewDeleteCurrentAPISessionCertificateOK creates DeleteCurrentAPISessionCertificateOK with default headers values
func NewDeleteCurrentAPISessionCertificateOK() *DeleteCurrentAPISessionCertificateOK {

	return &DeleteCurrentAPISessionCertificateOK{}
}

// WithPayload adds the payload to the delete current Api session certificate o k response
func (o *DeleteCurrentAPISessionCertificateOK) WithPayload(payload *rest_model.Empty) *DeleteCurrentAPISessionCertificateOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete current Api session certificate o k response
func (o *DeleteCurrentAPISessionCertificateOK) SetPayload(payload *rest_model.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteCurrentAPISessionCertificateOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteCurrentAPISessionCertificateBadRequestCode is the HTTP code returned for type DeleteCurrentAPISessionCertificateBadRequest
const DeleteCurrentAPISessionCertificateBadRequestCode int = 400

/*DeleteCurrentAPISessionCertificateBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response deleteCurrentApiSessionCertificateBadRequest
*/
type DeleteCurrentAPISessionCertificateBadRequest struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDeleteCurrentAPISessionCertificateBadRequest creates DeleteCurrentAPISessionCertificateBadRequest with default headers values
func NewDeleteCurrentAPISessionCertificateBadRequest() *DeleteCurrentAPISessionCertificateBadRequest {

	return &DeleteCurrentAPISessionCertificateBadRequest{}
}

// WithPayload adds the payload to the delete current Api session certificate bad request response
func (o *DeleteCurrentAPISessionCertificateBadRequest) WithPayload(payload *rest_model.APIErrorEnvelope) *DeleteCurrentAPISessionCertificateBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete current Api session certificate bad request response
func (o *DeleteCurrentAPISessionCertificateBadRequest) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteCurrentAPISessionCertificateBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteCurrentAPISessionCertificateUnauthorizedCode is the HTTP code returned for type DeleteCurrentAPISessionCertificateUnauthorized
const DeleteCurrentAPISessionCertificateUnauthorizedCode int = 401

/*DeleteCurrentAPISessionCertificateUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response deleteCurrentApiSessionCertificateUnauthorized
*/
type DeleteCurrentAPISessionCertificateUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDeleteCurrentAPISessionCertificateUnauthorized creates DeleteCurrentAPISessionCertificateUnauthorized with default headers values
func NewDeleteCurrentAPISessionCertificateUnauthorized() *DeleteCurrentAPISessionCertificateUnauthorized {

	return &DeleteCurrentAPISessionCertificateUnauthorized{}
}

// WithPayload adds the payload to the delete current Api session certificate unauthorized response
func (o *DeleteCurrentAPISessionCertificateUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *DeleteCurrentAPISessionCertificateUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete current Api session certificate unauthorized response
func (o *DeleteCurrentAPISessionCertificateUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteCurrentAPISessionCertificateUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}