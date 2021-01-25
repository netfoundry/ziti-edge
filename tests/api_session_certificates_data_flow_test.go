// +build apitests

/*
	Copyright NetFoundry, Inc.

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
	"crypto/tls"
	"github.com/openziti/edge/eid"
	"github.com/openziti/fabric/controller/xt_smartrouting"
	"github.com/openziti/sdk-golang/ziti"
	"sync"
	"testing"
	"time"
)

func Test_Api_Session_Certs_Data_Flow(t *testing.T) {
	ctx := NewTestContext(t)
	defer ctx.Teardown()
	ctx.StartServer()

	ctx.RequireAdminLogin()

	service := ctx.AdminSession.RequireNewServiceAccessibleToAll(xt_smartrouting.Name)

	ctx.CreateEnrollAndStartEdgeRouter()
	_, hostContext := ctx.AdminSession.RequireCreateSdkContext()
	listener, err := hostContext.Listen(service.Name)
	ctx.Req.NoError(err)

	testServer := newTestServer(listener, func(conn *testServerConn) error {
		for {
			name, eof := conn.ReadString(1024, 1*time.Minute)
			if eof {
				return conn.server.close()
			}

			if name == "quit" {
				conn.WriteString("ok", time.Second)
				return conn.server.close()
			}

			result := "hello, " + name
			conn.WriteString(result, time.Second)
		}
	})
	testServer.start()

	context := ziti.NewUpdbContextWithOpts("https://"+ctx.ApiHost, nil, &tls.Config{
		InsecureSkipVerify: true}, nil, ctx.AdminAuthenticator.Username, ctx.AdminAuthenticator.Password)

	t.Run("wrap connection", func(t *testing.T) {
		ctx.testContextChanged(t)
		conn := ctx.WrapConn(context.Dial(service.Name))

		t.Run("transfer data", func(t *testing.T) {
			ctx.testContextChanged(t)
			name := eid.New()

			var wg sync.WaitGroup

			wg.Add(5)

			go func() {
				defer wg.Done()
				conn.WriteString(name, time.Second)
			}()

			go func() {
				defer wg.Done()
				conn.ReadExpected("hello, "+name, time.Second)
			}()

			go func() {
				defer wg.Done()
				conn.WriteString("quit", time.Second)
			}()

			go func() {
				defer wg.Done()
				conn.ReadExpected("ok", time.Second)
			}()

			go func() {
				defer wg.Done()
				testServer.waitForDone(ctx, 5*time.Second)
			}()

			wg.Wait()
		})
	})

}
