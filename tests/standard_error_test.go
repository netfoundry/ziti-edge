// +build apitests

/*
	Copyright 2019 NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package tests

import (
	"github.com/netfoundry/ziti-edge/controller/apierror"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_StandardErrorMessages(t *testing.T) {
	ctx := NewTestContext(t)
	defer ctx.teardown()
	ctx.startServer()
	ctx.requireAdminLogin()

	t.Run("405 method not allowed returns a standard error", func(t *testing.T) {
		req := require.New(t)
		resp, err := ctx.AdminSession.newAuthenticatedJsonRequest(`{}`).Post("/")
		req.NoError(err)
		standardErrorJsonResponseTests(resp, apierror.MethodNotAllowedCode, apierror.MethodNotAllowedStatus, t)
	})
	t.Run("404 not found returns a standard error", func(t *testing.T) {
		req := require.New(t)
		resp, err := ctx.AdminSession.newAuthenticatedRequest().Get("/i-do-not-exist")
		req.NoError(err)
		standardErrorJsonResponseTests(resp, apierror.NotFoundCode, apierror.NotFoundStatus, t)
	})

}