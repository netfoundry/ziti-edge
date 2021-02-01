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

package edge_router_policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new edge router policy API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for edge router policy API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	CreateEdgeRouterPolicy(params *CreateEdgeRouterPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*CreateEdgeRouterPolicyCreated, error)

	DeleteEdgeRouterPolicy(params *DeleteEdgeRouterPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*DeleteEdgeRouterPolicyOK, error)

	DetailEdgeRouterPolicy(params *DetailEdgeRouterPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*DetailEdgeRouterPolicyOK, error)

	ListEdgeRouterPolicies(params *ListEdgeRouterPoliciesParams, authInfo runtime.ClientAuthInfoWriter) (*ListEdgeRouterPoliciesOK, error)

	ListEdgeRouterPolicyEdgeRouters(params *ListEdgeRouterPolicyEdgeRoutersParams, authInfo runtime.ClientAuthInfoWriter) (*ListEdgeRouterPolicyEdgeRoutersOK, error)

	ListEdgeRouterPolicyIdentities(params *ListEdgeRouterPolicyIdentitiesParams, authInfo runtime.ClientAuthInfoWriter) (*ListEdgeRouterPolicyIdentitiesOK, error)

	PatchEdgeRouterPolicy(params *PatchEdgeRouterPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*PatchEdgeRouterPolicyOK, error)

	UpdateEdgeRouterPolicy(params *UpdateEdgeRouterPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*UpdateEdgeRouterPolicyOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  CreateEdgeRouterPolicy creates an edge router policy resource

  Create an edge router policy resource. Requires admin access.
*/
func (a *Client) CreateEdgeRouterPolicy(params *CreateEdgeRouterPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*CreateEdgeRouterPolicyCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateEdgeRouterPolicyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "createEdgeRouterPolicy",
		Method:             "POST",
		PathPattern:        "/edge-router-policies",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateEdgeRouterPolicyReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*CreateEdgeRouterPolicyCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createEdgeRouterPolicy: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DeleteEdgeRouterPolicy deletes an edge router policy

  Delete an edge router policy by id. Requires admin access.
*/
func (a *Client) DeleteEdgeRouterPolicy(params *DeleteEdgeRouterPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*DeleteEdgeRouterPolicyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteEdgeRouterPolicyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "deleteEdgeRouterPolicy",
		Method:             "DELETE",
		PathPattern:        "/edge-router-policies/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteEdgeRouterPolicyReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DeleteEdgeRouterPolicyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteEdgeRouterPolicy: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DetailEdgeRouterPolicy retrieves a single edge router policy

  Retrieves a single edge router policy by id. Requires admin access.
*/
func (a *Client) DetailEdgeRouterPolicy(params *DetailEdgeRouterPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*DetailEdgeRouterPolicyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDetailEdgeRouterPolicyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "detailEdgeRouterPolicy",
		Method:             "GET",
		PathPattern:        "/edge-router-policies/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DetailEdgeRouterPolicyReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DetailEdgeRouterPolicyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for detailEdgeRouterPolicy: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListEdgeRouterPolicies lists edge router policies

  Retrieves a list of edge router policy resources; supports filtering, sorting, and pagination. Requires admin access.

*/
func (a *Client) ListEdgeRouterPolicies(params *ListEdgeRouterPoliciesParams, authInfo runtime.ClientAuthInfoWriter) (*ListEdgeRouterPoliciesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListEdgeRouterPoliciesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "listEdgeRouterPolicies",
		Method:             "GET",
		PathPattern:        "/edge-router-policies",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListEdgeRouterPoliciesReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListEdgeRouterPoliciesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listEdgeRouterPolicies: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListEdgeRouterPolicyEdgeRouters lists edge routers a policy affects

  Retrieves a list of edge routers an edge router policy resources affects; supports filtering, sorting, and pagination. Requires admin access.

*/
func (a *Client) ListEdgeRouterPolicyEdgeRouters(params *ListEdgeRouterPolicyEdgeRoutersParams, authInfo runtime.ClientAuthInfoWriter) (*ListEdgeRouterPolicyEdgeRoutersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListEdgeRouterPolicyEdgeRoutersParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "listEdgeRouterPolicyEdgeRouters",
		Method:             "GET",
		PathPattern:        "/edge-router-policies/{id}/edge-routers",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListEdgeRouterPolicyEdgeRoutersReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListEdgeRouterPolicyEdgeRoutersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listEdgeRouterPolicyEdgeRouters: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListEdgeRouterPolicyIdentities lists identities an edge router policy affects

  Retrieves a list of identities an edge router policy resources affects; supports filtering, sorting, and pagination. Requires admin access.

*/
func (a *Client) ListEdgeRouterPolicyIdentities(params *ListEdgeRouterPolicyIdentitiesParams, authInfo runtime.ClientAuthInfoWriter) (*ListEdgeRouterPolicyIdentitiesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListEdgeRouterPolicyIdentitiesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "listEdgeRouterPolicyIdentities",
		Method:             "GET",
		PathPattern:        "/edge-router-policies/{id}/identities",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListEdgeRouterPolicyIdentitiesReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListEdgeRouterPolicyIdentitiesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listEdgeRouterPolicyIdentities: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PatchEdgeRouterPolicy updates the supplied fields on an edge router policy

  Update the supplied fields on an edge router policy. Requires admin access.
*/
func (a *Client) PatchEdgeRouterPolicy(params *PatchEdgeRouterPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*PatchEdgeRouterPolicyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPatchEdgeRouterPolicyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "patchEdgeRouterPolicy",
		Method:             "PATCH",
		PathPattern:        "/edge-router-policies/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PatchEdgeRouterPolicyReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PatchEdgeRouterPolicyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for patchEdgeRouterPolicy: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UpdateEdgeRouterPolicy updates all fields on an edge router policy

  Update all fields on an edge router policy by id. Requires admin access.
*/
func (a *Client) UpdateEdgeRouterPolicy(params *UpdateEdgeRouterPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*UpdateEdgeRouterPolicyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateEdgeRouterPolicyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "updateEdgeRouterPolicy",
		Method:             "PUT",
		PathPattern:        "/edge-router-policies/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateEdgeRouterPolicyReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*UpdateEdgeRouterPolicyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateEdgeRouterPolicy: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
