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
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// ListPostureChecksOKCode is the HTTP code returned for type ListPostureChecksOK
const ListPostureChecksOKCode int = 200

/*ListPostureChecksOK A list of posture checks

swagger:response listPostureChecksOK
*/
type ListPostureChecksOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.ListPostureCheckEnvelope `json:"body,omitempty"`
}

// NewListPostureChecksOK creates ListPostureChecksOK with default headers values
func NewListPostureChecksOK() *ListPostureChecksOK {

	return &ListPostureChecksOK{}
}

// WithPayload adds the payload to the list posture checks o k response
func (o *ListPostureChecksOK) WithPayload(payload *rest_model.ListPostureCheckEnvelope) *ListPostureChecksOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list posture checks o k response
func (o *ListPostureChecksOK) SetPayload(payload *rest_model.ListPostureCheckEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListPostureChecksOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}