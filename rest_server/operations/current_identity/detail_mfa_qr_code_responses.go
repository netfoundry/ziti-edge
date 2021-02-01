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
)

// DetailMfaQrCodeOKCode is the HTTP code returned for type DetailMfaQrCodeOK
const DetailMfaQrCodeOKCode int = 200

/*DetailMfaQrCodeOK OK

swagger:response detailMfaQrCodeOK
*/
type DetailMfaQrCodeOK struct {
}

// NewDetailMfaQrCodeOK creates DetailMfaQrCodeOK with default headers values
func NewDetailMfaQrCodeOK() *DetailMfaQrCodeOK {

	return &DetailMfaQrCodeOK{}
}

// WriteResponse to the client
func (o *DetailMfaQrCodeOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}

// DetailMfaQrCodeNotFoundCode is the HTTP code returned for type DetailMfaQrCodeNotFound
const DetailMfaQrCodeNotFoundCode int = 404

/*DetailMfaQrCodeNotFound No MFA enrollment or MFA enrollment is completed

swagger:response detailMfaQrCodeNotFound
*/
type DetailMfaQrCodeNotFound struct {
}

// NewDetailMfaQrCodeNotFound creates DetailMfaQrCodeNotFound with default headers values
func NewDetailMfaQrCodeNotFound() *DetailMfaQrCodeNotFound {

	return &DetailMfaQrCodeNotFound{}
}

// WriteResponse to the client
func (o *DetailMfaQrCodeNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(404)
}
