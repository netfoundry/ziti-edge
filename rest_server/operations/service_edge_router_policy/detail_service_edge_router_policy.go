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

package service_edge_router_policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// DetailServiceEdgeRouterPolicyHandlerFunc turns a function with the right signature into a detail service edge router policy handler
type DetailServiceEdgeRouterPolicyHandlerFunc func(DetailServiceEdgeRouterPolicyParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn DetailServiceEdgeRouterPolicyHandlerFunc) Handle(params DetailServiceEdgeRouterPolicyParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// DetailServiceEdgeRouterPolicyHandler interface for that can handle valid detail service edge router policy params
type DetailServiceEdgeRouterPolicyHandler interface {
	Handle(DetailServiceEdgeRouterPolicyParams, interface{}) middleware.Responder
}

// NewDetailServiceEdgeRouterPolicy creates a new http.Handler for the detail service edge router policy operation
func NewDetailServiceEdgeRouterPolicy(ctx *middleware.Context, handler DetailServiceEdgeRouterPolicyHandler) *DetailServiceEdgeRouterPolicy {
	return &DetailServiceEdgeRouterPolicy{Context: ctx, Handler: handler}
}

/*DetailServiceEdgeRouterPolicy swagger:route GET /service-edge-router-policies/{id} Service Edge Router Policy detailServiceEdgeRouterPolicy

Retrieves a single service edge policy

Retrieves a single service edge policy by id. Requires admin access.

*/
type DetailServiceEdgeRouterPolicy struct {
	Context *middleware.Context
	Handler DetailServiceEdgeRouterPolicyHandler
}

func (o *DetailServiceEdgeRouterPolicy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewDetailServiceEdgeRouterPolicyParams()

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
