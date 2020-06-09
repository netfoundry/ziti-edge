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

package identity

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// GetIdentityPolicyAdviceHandlerFunc turns a function with the right signature into a get identity policy advice handler
type GetIdentityPolicyAdviceHandlerFunc func(GetIdentityPolicyAdviceParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn GetIdentityPolicyAdviceHandlerFunc) Handle(params GetIdentityPolicyAdviceParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// GetIdentityPolicyAdviceHandler interface for that can handle valid get identity policy advice params
type GetIdentityPolicyAdviceHandler interface {
	Handle(GetIdentityPolicyAdviceParams, interface{}) middleware.Responder
}

// NewGetIdentityPolicyAdvice creates a new http.Handler for the get identity policy advice operation
func NewGetIdentityPolicyAdvice(ctx *middleware.Context, handler GetIdentityPolicyAdviceHandler) *GetIdentityPolicyAdvice {
	return &GetIdentityPolicyAdvice{Context: ctx, Handler: handler}
}

/*GetIdentityPolicyAdvice swagger:route GET /identities/{id}/policy-advice/{serviceId} Identity getIdentityPolicyAdvice

Analyze policies relating the given identity and service

Analyzes policies to see if the given identity should be able to dial or bind the given service. |
Will check services policies to see if the identity can access the service. Will check edge router policies |
to check if the identity and service have access to common edge routers so that a connnection can be made. |
Will also check if at least one edge router is on-line. Requires admin access.


*/
type GetIdentityPolicyAdvice struct {
	Context *middleware.Context
	Handler GetIdentityPolicyAdviceHandler
}

func (o *GetIdentityPolicyAdvice) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetIdentityPolicyAdviceParams()

	uprinc, aCtx, err := o.Context.Authorize(r, route)
	if err != nil {
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}
	if aCtx != nil {
		r = aCtx
	}
	var principal interface{}
	if uprinc != nil {
		principal = uprinc
	}

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params, principal) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
