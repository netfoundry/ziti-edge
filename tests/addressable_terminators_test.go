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
	"fmt"
	"github.com/openziti/fabric/controller/xt_smartrouting"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/pkg/errors"
	"net"
	"testing"
	"time"
)

func Test_AddressableTerminators(t *testing.T) {
	ctx := NewTestContext(t)
	defer ctx.Teardown()
	ctx.StartServer()
	ctx.RequireAdminLogin()

	service := ctx.AdminSession.RequireNewServiceAccessibleToAll(xt_smartrouting.Name)
	fmt.Printf("service id: %v\n", service.Id)

	ctx.CreateEnrollAndStartEdgeRouter()

	type host struct {
		id       *identity
		context  ziti.Context
		listener net.Listener
	}

	var hosts []*host
	var err error

	for i := 0; i < 2; i++ {
		host := &host{}
		hosts = append(hosts, host)

		host.id, host.context = ctx.AdminSession.RequireCreateSdkContext()
		host.listener, err = host.context.ListenWithOptions(service.Name, &ziti.ListenOptions{
			BindUsingEdgeIdentity: true,
		})
		ctx.Req.NoError(err)
	}

	type client struct {
		id      *identity
		context ziti.Context
	}

	var clients []*client

	for i := 0; i < 3; i++ {
		client := &client{}
		clients = append(clients, client)
		client.id, client.context = ctx.AdminSession.RequireCreateSdkContext()
	}

	waitForConn := func(listener net.Listener, timeout time.Duration) (net.Conn, error) {
		connC := make(chan net.Conn, 1)
		errC := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				errC <- err
			} else {
				connC <- conn
			}
		}()

		select {
		case conn := <-connC:
			return conn, nil
		case err := <-errC:
			return nil, err
		case <-time.After(timeout):
			return nil, errors.Errorf("timed out waiting for connection after %v", timeout)
		}
	}

	for _, client := range clients {
		for _, host := range hosts {
			conn, err := client.context.DialWithOptions(service.Name, &ziti.DialOptions{
				Identity: host.id.name,
			})
			ctx.Req.NoError(err)
			hostConn, err := waitForConn(host.listener, time.Second)
			ctx.Req.NoError(err)
			ctx.Req.Equal(client.id.name, hostConn.RemoteAddr().String())
			ctx.Req.NoError(conn.Close())
			ctx.Req.NoError(hostConn.Close())
		}
	}
}

func Test_AddressableTerminatorSameIdentity(t *testing.T) {
	ctx := NewTestContext(t)
	defer ctx.Teardown()
	ctx.StartServer()
	ctx.RequireAdminLogin()

	service := ctx.AdminSession.RequireNewServiceAccessibleToAll(xt_smartrouting.Name)
	fmt.Printf("service id: %v\n", service.Id)

	ctx.CreateEnrollAndStartEdgeRouter()

	errorC := make(chan error, 1)
	errorHandler := func(err error) {
		select {
		case errorC <- err:
		default:
		}
	}

	identity, context := ctx.AdminSession.RequireCreateSdkContext()
	listener, err := context.ListenWithOptions(service.Name, &ziti.ListenOptions{
		BindUsingEdgeIdentity: true,
		ConnectTimeout:        5 * time.Second,
	})
	ctx.Req.NoError(err)
	listener.(edge.SessionListener).SetErrorEventHandler(errorHandler)
	defer func() { _ = listener.Close() }()

	context2 := ziti.NewContextWithConfig(identity.config)
	listener2, err := context2.ListenWithOptions(service.Name, &ziti.ListenOptions{
		BindUsingEdgeIdentity: true,
		ConnectTimeout:        5 * time.Second,
	})
	listener2.(edge.SessionListener).SetErrorEventHandler(errorHandler)
	ctx.Req.NoError(err)
	defer func() { _ = listener2.Close() }()

	select {
	case err = <-errorC:
	case <-time.After(5 * time.Second):
		err = nil
	}
	ctx.Req.NoError(err)
}

func Test_AddressableTerminatorDifferentIdentity(t *testing.T) {
	ctx := NewTestContext(t)
	defer ctx.Teardown()
	ctx.StartServer()
	ctx.RequireAdminLogin()

	service := ctx.AdminSession.RequireNewServiceAccessibleToAll(xt_smartrouting.Name)
	fmt.Printf("service id: %v\n", service.Id)

	ctx.CreateEnrollAndStartEdgeRouter()

	errorC := make(chan error, 1)
	errorHandler := func(err error) {
		select {
		case errorC <- err:
		default:
		}
	}

	_, context := ctx.AdminSession.RequireCreateSdkContext()
	listener, err := context.ListenWithOptions(service.Name, &ziti.ListenOptions{
		Identity:       "foobar",
		ConnectTimeout: 5 * time.Second,
	})
	listener.(edge.SessionListener).SetErrorEventHandler(errorHandler)
	ctx.Req.NoError(err)
	defer func() { _ = listener.Close() }()

	_, context2 := ctx.AdminSession.RequireCreateSdkContext()
	listener2, err := context2.ListenWithOptions(service.Name, &ziti.ListenOptions{
		Identity:       "foobar",
		ConnectTimeout: 5 * time.Second,
	})
	ctx.Req.NoError(err)
	listener2.(edge.SessionListener).SetErrorEventHandler(errorHandler)
	defer func() { _ = listener2.Close() }()

	select {
	case err = <-errorC:
	case <-time.After(5 * time.Second):
		err = nil
	}
	ctx.Req.Error(err)
	ctx.Req.Contains(err.Error(), "shared identity foobar belongs to different identity")
}