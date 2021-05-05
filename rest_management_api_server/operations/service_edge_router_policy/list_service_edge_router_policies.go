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

// ListServiceEdgeRouterPoliciesHandlerFunc turns a function with the right signature into a list service edge router policies handler
type ListServiceEdgeRouterPoliciesHandlerFunc func(ListServiceEdgeRouterPoliciesParams, interface{}) middleware.Responder

// Handle executing the request and returning a response
func (fn ListServiceEdgeRouterPoliciesHandlerFunc) Handle(params ListServiceEdgeRouterPoliciesParams, principal interface{}) middleware.Responder {
	return fn(params, principal)
}

// ListServiceEdgeRouterPoliciesHandler interface for that can handle valid list service edge router policies params
type ListServiceEdgeRouterPoliciesHandler interface {
	Handle(ListServiceEdgeRouterPoliciesParams, interface{}) middleware.Responder
}

// NewListServiceEdgeRouterPolicies creates a new http.Handler for the list service edge router policies operation
func NewListServiceEdgeRouterPolicies(ctx *middleware.Context, handler ListServiceEdgeRouterPoliciesHandler) *ListServiceEdgeRouterPolicies {
	return &ListServiceEdgeRouterPolicies{Context: ctx, Handler: handler}
}

/* ListServiceEdgeRouterPolicies swagger:route GET /service-edge-router-policies Service Edge Router Policy listServiceEdgeRouterPolicies

List service edge router policies

Retrieves a list of service edge router policy resources; supports filtering, sorting, and pagination. Requires admin access.


*/
type ListServiceEdgeRouterPolicies struct {
	Context *middleware.Context
	Handler ListServiceEdgeRouterPoliciesHandler
}

func (o *ListServiceEdgeRouterPolicies) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewListServiceEdgeRouterPoliciesParams()
	uprinc, aCtx, err := o.Context.Authorize(r, route)
	if err != nil {
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}
	if aCtx != nil {
		*r = *aCtx
	}
	var principal interface{}
	if uprinc != nil {
		principal = uprinc.(interface{}) // this is really a interface{}, I promise
	}

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params, principal) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}