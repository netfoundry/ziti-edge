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

package edge_router

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// ListEdgeRouterIdentitiesOKCode is the HTTP code returned for type ListEdgeRouterIdentitiesOK
const ListEdgeRouterIdentitiesOKCode int = 200

/*ListEdgeRouterIdentitiesOK A list of identities

swagger:response listEdgeRouterIdentitiesOK
*/
type ListEdgeRouterIdentitiesOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.ListIdentitiesEnvelope `json:"body,omitempty"`
}

// NewListEdgeRouterIdentitiesOK creates ListEdgeRouterIdentitiesOK with default headers values
func NewListEdgeRouterIdentitiesOK() *ListEdgeRouterIdentitiesOK {

	return &ListEdgeRouterIdentitiesOK{}
}

// WithPayload adds the payload to the list edge router identities o k response
func (o *ListEdgeRouterIdentitiesOK) WithPayload(payload *rest_model.ListIdentitiesEnvelope) *ListEdgeRouterIdentitiesOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list edge router identities o k response
func (o *ListEdgeRouterIdentitiesOK) SetPayload(payload *rest_model.ListIdentitiesEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListEdgeRouterIdentitiesOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ListEdgeRouterIdentitiesUnauthorizedCode is the HTTP code returned for type ListEdgeRouterIdentitiesUnauthorized
const ListEdgeRouterIdentitiesUnauthorizedCode int = 401

/*ListEdgeRouterIdentitiesUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response listEdgeRouterIdentitiesUnauthorized
*/
type ListEdgeRouterIdentitiesUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewListEdgeRouterIdentitiesUnauthorized creates ListEdgeRouterIdentitiesUnauthorized with default headers values
func NewListEdgeRouterIdentitiesUnauthorized() *ListEdgeRouterIdentitiesUnauthorized {

	return &ListEdgeRouterIdentitiesUnauthorized{}
}

// WithPayload adds the payload to the list edge router identities unauthorized response
func (o *ListEdgeRouterIdentitiesUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *ListEdgeRouterIdentitiesUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list edge router identities unauthorized response
func (o *ListEdgeRouterIdentitiesUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListEdgeRouterIdentitiesUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ListEdgeRouterIdentitiesNotFoundCode is the HTTP code returned for type ListEdgeRouterIdentitiesNotFound
const ListEdgeRouterIdentitiesNotFoundCode int = 404

/*ListEdgeRouterIdentitiesNotFound The requested resource does not exist

swagger:response listEdgeRouterIdentitiesNotFound
*/
type ListEdgeRouterIdentitiesNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewListEdgeRouterIdentitiesNotFound creates ListEdgeRouterIdentitiesNotFound with default headers values
func NewListEdgeRouterIdentitiesNotFound() *ListEdgeRouterIdentitiesNotFound {

	return &ListEdgeRouterIdentitiesNotFound{}
}

// WithPayload adds the payload to the list edge router identities not found response
func (o *ListEdgeRouterIdentitiesNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *ListEdgeRouterIdentitiesNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list edge router identities not found response
func (o *ListEdgeRouterIdentitiesNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListEdgeRouterIdentitiesNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
