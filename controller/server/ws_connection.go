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

package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/buger/jsonparser"
	"github.com/go-openapi/runtime"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/mitchellh/mapstructure"
	"github.com/openziti/edge/controller/apierror"
	"github.com/openziti/edge/controller/config"
	"github.com/openziti/edge/controller/env"
	"github.com/openziti/edge/controller/internal/permissions"
	"github.com/openziti/edge/controller/internal/routes"
	"github.com/openziti/edge/controller/model"
	"github.com/openziti/edge/controller/response"
	"github.com/openziti/edge/internal/version"
	"github.com/openziti/edge/rest_model"
	"github.com/openziti/fabric/controller/models"
	"github.com/openziti/foundation/channel2"
	"github.com/openziti/foundation/transport"
	"github.com/openziti/foundation/util/stringz"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// TLS 1.0 - 1.2 cipher suites supported by ziti-sdk-js
const (
	TLS_RSA_WITH_AES_128_CBC_SHA uint16 = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA uint16 = 0x0035
)

var (
	errClosing = errors.New(`Closing`)
)

// safeBuffer adds thread-safety to *bytes.Buffer
type safeBuffer struct {
	buf *bytes.Buffer
	log *logrus.Entry
	sync.Mutex
}

// Read reads the next len(p) bytes from the buffer or until the buffer is drained.
func (s *safeBuffer) Read(p []byte) (int, error) {
	s.Lock()
	defer s.Unlock()
	return s.buf.Read(p)
}

// Write appends the contents of p to the buffer.
func (s *safeBuffer) Write(p []byte) (int, error) {
	s.Lock()
	defer s.Unlock()
	return s.buf.Write(p)
}

// Len returns the number of bytes of the unread portion of the buffer.
func (s *safeBuffer) Len() int {
	s.Lock()
	defer s.Unlock()
	return s.buf.Len()
}

// Reset resets the buffer to be empty.
func (s *safeBuffer) Reset() {
	s.Lock()
	s.buf.Reset()
	s.Unlock()
}

// WSConnection wraps gorilla websocket to provide io.ReadWriteCloser
type WSConnection struct {
	config                   *config.Config
	AppEnv                   *env.AppEnv
	tlsConfig                *tls.Config
	ws                       *websocket.Conn
	tlsConn                  *tls.Conn
	tlsConnHandshakeComplete bool
	logger                   *logrus.Entry
	rxbuf                    *safeBuffer
	txbuf                    *safeBuffer
	tlsrxbuf                 *safeBuffer
	tlstxbuf                 *safeBuffer
	done                     chan struct{}
	wmutex                   sync.Mutex
	rmutex                   sync.Mutex
	tlswmutex                sync.Mutex
	tlsrmutex                sync.Mutex
	readCallDepth            int32
	writeCallDepth           int32
}

// Read implements io.Reader by wrapping websocket messages in a buffer.
func (c *WSConnection) Read(p []byte) (n int, err error) {

	currentDepth := atomic.AddInt32(&c.readCallDepth, 1)
	c.logger.Tracef("Read() start currentDepth[%d]", currentDepth)

	if c.rxbuf.Len() == 0 {
		var r io.Reader
		c.rxbuf.Reset()
		if c.tlsConnHandshakeComplete {
			if currentDepth == 1 {
				c.tlsrmutex.Lock()
				defer c.tlsrmutex.Unlock()
			} else if currentDepth == 2 {
				c.rmutex.Lock()
				defer c.rmutex.Unlock()
			}
		} else {
			c.rmutex.Lock()
			defer c.rmutex.Unlock()
		}
		select {
		case <-c.done:
			err = errClosing
		default:
			err = c.ws.SetReadDeadline(time.Now().Add(c.config.WSApi.ReadTimeout))
			if err == nil {
				if c.tlsConnHandshakeComplete && currentDepth == 1 {
					n, err = c.tlsConn.Read(p)
					atomic.SwapInt32(&c.readCallDepth, (c.readCallDepth - 1))
					c.logger.Tracef("Read() end currentDepth[%d]", currentDepth)

					return n, err
				}
				_, r, err = c.ws.NextReader()
			}
		}
		if err != nil {
			return n, err
		}
		_, err = io.Copy(c.rxbuf, r)
		if err != nil {
			return n, err
		}
	}

	atomic.SwapInt32(&c.readCallDepth, (c.readCallDepth - 1))

	c.logger.Tracef("Read() end currentDepth[%d]", currentDepth)

	return c.rxbuf.Read(p)
}

// Write implements io.Writer and sends binary messages only.
func (c *WSConnection) Write(p []byte) (n int, err error) {
	return c.write(websocket.BinaryMessage, p)
}

// write wraps the websocket writer.
func (c *WSConnection) write(messageType int, p []byte) (n int, err error) {
	var txbufLen int
	currentDepth := atomic.AddInt32(&c.writeCallDepth, 1)
	c.logger.Tracef("Write() start currentDepth[%d] len[%d] data[%o]", c.writeCallDepth, len(p), p)

	if c.tlsConnHandshakeComplete {
		if currentDepth == 1 {
			c.tlswmutex.Lock()
			defer c.tlswmutex.Unlock()
		} else if currentDepth == 2 {
			c.wmutex.Lock()
			defer c.wmutex.Unlock()
		}
	} else {
		c.wmutex.Lock()
		defer c.wmutex.Unlock()
	}

	select {
	case <-c.done:
		err = errClosing
	default:
		var txbufLen int

		if !c.tlsConnHandshakeComplete {
			c.tlstxbuf.Write(p)
			txbufLen = c.tlstxbuf.Len()
			c.logger.Tracef("Write() doing TLS handshake (buffering); currentDepth[%d] txbufLen[%d] data[%o]", c.writeCallDepth, txbufLen, p)
		} else if currentDepth == 1 { // if at TLS level (1st level)
			c.tlstxbuf.Write(p)
			txbufLen = c.tlstxbuf.Len()
			c.logger.Tracef("Write() doing TLS write; currentDepth[%d] txbufLen[%d] data[%o]", c.writeCallDepth, txbufLen, p)
		} else { // if at websocket level (2nd level)
			c.txbuf.Write(p)
			txbufLen = c.txbuf.Len()
			c.logger.Tracef("Write() doing raw write; currentDepth[%d] txbufLen[%d] data[%o]", c.writeCallDepth, txbufLen, p)
		}

		if txbufLen > 20 { // TEMP HACK:  (until I refactor the JS-SDK to accept the message section and data section in separate salvos)
			err = c.ws.SetWriteDeadline(time.Now().Add(c.config.WSApi.WriteTimeout))
			if err == nil {
				if !c.tlsConnHandshakeComplete {
					m := make([]byte, txbufLen)
					c.tlstxbuf.Read(m)
					c.logger.Tracef("Write() doing TLS handshake (to websocket); currentDepth[%d] txbufLen[%d] data[%o]", c.writeCallDepth, txbufLen, m)
					err = c.ws.WriteMessage(messageType, m)
				} else if currentDepth == 1 {
					m := make([]byte, txbufLen)
					c.tlstxbuf.Read(m)
					c.logger.Tracef("Write() doing TLS write (to conn); currentDepth[%d] txbufLen[%d] data[%o]", c.writeCallDepth, txbufLen, m)
					n, err = c.tlsConn.Write(m)
					atomic.SwapInt32(&c.writeCallDepth, (c.writeCallDepth - 1))
					c.logger.Tracef("write() end TLS write currentDepth[%d]", c.writeCallDepth)

					return n, err
				} else {
					m := make([]byte, txbufLen)
					c.txbuf.Read(m)
					c.logger.Tracef("Write() doing raw write (to websocket); currentDepth[%d] len[%d]", c.writeCallDepth, len(m))
					err = c.ws.WriteMessage(messageType, m)
				}
			}
		}
	}
	if err == nil {
		n = txbufLen
	}
	atomic.SwapInt32(&c.writeCallDepth, (c.writeCallDepth - 1))
	c.logger.Tracef("Write() end currentDepth[%d]", c.writeCallDepth)

	return n, err
}

// Close implements io.Closer and closes the underlying connection.
func (c *WSConnection) Close() error {
	c.logger.Debug("closing websocket")

	c.rmutex.Lock()
	c.wmutex.Lock()
	defer func() {
		c.rmutex.Unlock()
		c.wmutex.Unlock()
	}()
	select {
	case <-c.done:
		return errClosing
	default:
		close(c.done)
	}
	return c.ws.Close()
}

// pinger sends ping messages on an interval for client keep-alive.
func (c *WSConnection) pinger() {
	ticker := time.NewTicker(c.config.WSApi.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.logger.Trace("sending websocket Ping")
			if _, err := c.write(websocket.PingMessage, []byte{}); err != nil {
				_ = c.Close()
			}
		}
	}
}

func (c *WSConnection) handleVersion(method string, path string, queryParams string, body string) {
}

func (c *WSConnection) RespondWithError(e error, statusCode int) *WSRestResponse {
	resp := NewWSRestResponse()
	resp.WriteHeader(statusCode)
	// var envelope interface{}
	producer := runtime.JSONProducer()
	// err := producer.Produce(resp, envelope)
	// return resp

	var apiError *apierror.ApiError
	var ok bool

	if apiError, ok = e.(*apierror.ApiError); !ok {
		apiError = apierror.NewUnhandled(e)
	}

	data := &rest_model.APIErrorEnvelope{
		Error: apiError.ToRestModel("requestId"),
		Meta: &rest_model.Meta{
			APIEnrolmentVersion: version.GetApiVersion(),
			APIVersion:          version.GetApiEnrollmentVersion(),
		},
	}

	resp.Header().Set("content-type", "application/json")

	resp.WriteHeader(apiError.Status)
	err := producer.Produce(resp, data)

	if err != nil {
		c.logger.WithError(err).Error("could not respond with error, producer errored")
	}

	return resp
}

type ConfigTypesObj struct {
	ConfigTypesArray []string `json:"configTypes"`
}

func (c *WSConnection) handleAuthenticate(rc *response.RequestContext, b []byte) *WSRestResponse {
	// start := time.Now()
	c.logger.Debug("handleAuthenticate() entered")

	var ct map[string]interface{}
	err := json.Unmarshal(b, &ct)
	c.logger.Debugf("handleAuthenticate() ct is: %v", ct)
	if err != nil {
		// rc.RespondWithError(err)
		// return
	}

	cto := ConfigTypesObj{}
	err = json.Unmarshal(b, &cto)
	c.logger.Debugf("handleAuthenticate() ConfigTypesObj is: %v", cto)

	if err != nil {
		// rc.RespondWithError(err)
		// return
	}

	authContext := &model.AuthContextHttp{
		Method:  "cert",
		Data:    ct,
		Certs:   c.PeerCertificates(),
		Headers: nil,
	}

	identity, err := c.AppEnv.Handlers.Authenticator.IsAuthorized(authContext)

	if err != nil {
		return c.RespondWithError(err, http.StatusUnauthorized)
	}

	if identity == nil {
		// rc.RespondWithApiError(apierror.NewUnauthorized())
		// return
	}

	if identity.EnvInfo == nil {
		identity.EnvInfo = &model.EnvInfo{}
	}

	if identity.SdkInfo == nil {
		identity.SdkInfo = &model.SdkInfo{}
	}

	if dataMap := authContext.GetData(); dataMap != nil {
		shouldUpdate := false

		if envInfoInterface := dataMap["envInfo"]; envInfoInterface != nil {
			if envInfo := envInfoInterface.(map[string]interface{}); envInfo != nil {
				if err := mapstructure.Decode(envInfo, &identity.EnvInfo); err != nil {
					c.logger.WithError(err).Error("error processing env info")
				}
				shouldUpdate = true
			}
		}

		if sdkInfoInterface := dataMap["sdkInfo"]; sdkInfoInterface != nil {
			if sdkInfo := sdkInfoInterface.(map[string]interface{}); sdkInfo != nil {
				if err := mapstructure.Decode(sdkInfo, &identity.SdkInfo); err != nil {
					c.logger.WithError(err).Error("error processing sdk info")
				}
				shouldUpdate = true
			}
		}

		if shouldUpdate {
			if err := c.AppEnv.GetHandlers().Identity.PatchInfo(identity); err != nil {
				c.logger.WithError(err).Errorf("failed to update sdk/env info on identity [%s] auth", identity.Id)
			}
		}
	}

	token := uuid.New().String()
	configTypes := map[string]struct{}{}

	if cto.ConfigTypesArray != nil {
		configTypes = c.mapConfigTypeNamesToIds(c.AppEnv, cto.ConfigTypesArray, identity.Id)
	}
	c.logger.Debugf("cto.ConfigTypesArray: %v", cto.ConfigTypesArray)
	c.logger.Debugf("configTypes: %v", configTypes)

	remoteIpStr := ""
	if remoteIp, _, err := net.SplitHostPort(c.RemoteAddr().String()); err == nil {
		remoteIpStr = remoteIp
	}

	c.logger.Debugf("client %v requesting configTypes: %v", identity.Name, configTypes)
	s := &model.ApiSession{
		IdentityId:  identity.Id,
		Token:       token,
		ConfigTypes: configTypes,
		IPAddress:   remoteIpStr,
	}
	sessionId, err := c.AppEnv.Handlers.ApiSession.Create(s)
	c.logger.Debugf("sessionId: %v", sessionId)

	if err != nil {
		// rc.RespondWithError(err)
		// return
	}

	session, err := c.AppEnv.Handlers.ApiSession.Read(sessionId)

	if err != nil {
		c.logger.WithField("cause", err).Error("loading session by id resulted in an error")
		// rc.RespondWithApiError(apierror.NewUnauthorized())
	}

	apiSession := routes.MapToCurrentApiSessionRestModel(session, c.AppEnv.Config.SessionTimeoutDuration())

	envelope := &rest_model.CurrentAPISessionDetailEnvelope{Data: apiSession, Meta: &rest_model.Meta{}}
	c.logger.Debugf("envelope: %v", envelope)

	expiration := time.Time(*apiSession.ExpiresAt)
	cookie := http.Cookie{Name: c.AppEnv.AuthCookieName, Value: token, Expires: expiration}

	resp := NewWSRestResponse()

	resp.Header().Set(c.AppEnv.AuthHeaderName, session.Token)
	http.SetCookie(resp, &cookie)
	// ro.createTimer.UpdateSince(start)

	// rc.Respond(envelope, http.StatusOK)

	resp.WriteHeader(http.StatusOK)

	producer := runtime.JSONProducer()

	err = producer.Produce(resp, envelope)

	c.logger.Debugf("session.Token: %v", session.Token)

	return resp
}

func (c *WSConnection) mapConfigTypeNamesToIds(ae *env.AppEnv, values []string, identityId string) map[string]struct{} {
	var result []string
	if stringz.Contains(values, "all") {
		result = []string{"all"}
	} else {
		for _, val := range values {
			if configType, _ := ae.GetHandlers().ConfigType.Read(val); configType != nil {
				result = append(result, val)
			} else if configType, _ := ae.GetHandlers().ConfigType.ReadByName(val); configType != nil {
				result = append(result, configType.Id)
			} else {
				c.logger.Debugf("user %v submitted %v as a config type of interest, but no matching records found", identityId, val)
			}
		}
	}
	return stringz.SliceToSet(result)
}

func (c *WSConnection) GetModelQueryOptionsFromRequest(queryParams string) (*routes.QueryOptions, error) {
	queryParamsMap, err := url.ParseQuery(queryParams)
	if err != nil {
		return nil, err
	}

	filter := queryParamsMap.Get("filter")
	sort := queryParamsMap.Get("sort")

	pg, err := c.GetRequestPaging(queryParamsMap)

	if err != nil {
		return nil, err
	}

	return &routes.QueryOptions{
		Predicate: filter,
		Sort:      sort,
		Paging:    pg,
	}, nil
}

func (c *WSConnection) GetRequestPaging(queryParamsMap url.Values) (*routes.Paging, error) {
	l := queryParamsMap.Get("limit")
	o := queryParamsMap.Get("offset")

	var p *routes.Paging

	if l != "" {
		i, err := strconv.ParseInt(l, 10, 64)

		if err != nil {
			return nil, &apierror.ApiError{
				Code:        apierror.InvalidPaginationCode,
				Message:     apierror.InvalidPaginationMessage,
				Cause:       apierror.NewFieldError("could not parse limit, value is not an integer", "limit", l),
				AppendCause: true,
			}
		}
		p = &routes.Paging{}
		p.Limit = i
	}

	if o != "" {
		i, err := strconv.ParseInt(o, 10, 64)

		if err != nil {
			return nil, &apierror.ApiError{
				Code:        apierror.InvalidPaginationCode,
				Message:     apierror.InvalidPaginationMessage,
				Cause:       apierror.NewFieldError("could not parse offset, value is not an integer", "offset", o),
				AppendCause: true,
			}
		}
		if p == nil {
			p = &routes.Paging{}
		}
		p.Offset = i
	}

	return p, nil
}

func (c *WSConnection) handleServices(rc *response.RequestContext, queryParams string, sessionToken string, b []byte) *WSRestResponse {
	c.logger.Debug("handleServices() entered")

	apiSession, err := c.AppEnv.GetHandlers().ApiSession.ReadByToken(sessionToken)

	configTypes := apiSession.ConfigTypes
	c.logger.Debugf("configTypes: %v", configTypes)

	var ct map[string]interface{}
	err = json.Unmarshal(b, &ct)
	if err != nil {
		// 	// rc.RespondWithError(err)
		// 	// return
	}

	authContext := &model.AuthContextHttp{
		Method: "cert",
		Data:   ct,
		// Data:    configTypes,
		Certs:   c.PeerCertificates(),
		Headers: nil,
	}

	identity, err := c.AppEnv.Handlers.Authenticator.IsAuthorized(authContext)

	queryOptions, err := c.GetModelQueryOptionsFromRequest(queryParams)

	query, err := queryOptions.GetFullQuery(c.AppEnv.Handlers.EdgeService.GetStore())
	if err != nil {
		// rc.RespondWithError(err)
		// return
	}

	var apiEntities []interface{}
	var qmd *models.QueryMetaData
	result, err := c.AppEnv.Handlers.EdgeService.PublicQueryForIdentity(identity, configTypes, query)
	if err != nil {
		// pfxlog.Logger().Errorf("error executing list query: %+v", err)
		// return nil, err

		// rc.RespondWithError(err)
		// return
	}
	apiEntities, err = routes.MapServicesToRestEntity(c.AppEnv, rc, result.Services)
	if err != nil {
		// rc.RespondWithError(err)
		// return
	}
	qmd = &result.QueryMetaData
	qr := routes.NewQueryResult(apiEntities, qmd)

	c.logger.Debugf("query result: %v", qr)

	meta := &rest_model.Meta{
		Pagination: &rest_model.Pagination{
			Limit:      &result.Limit,
			Offset:     &result.Offset,
			TotalCount: &result.Count,
		},
		FilterableFields: result.FilterableFields,
	}

	var envelope interface{}

	switch reflect.TypeOf(qr.Result).Kind() {
	case reflect.Slice:
		slice := reflect.ValueOf(qr.Result)

		//noinspection GoPreferNilSlice
		elements := []interface{}{}
		for i := 0; i < slice.Len(); i++ {
			elem := slice.Index(i)
			elements = append(elements, elem.Interface())
		}

		envelope = c.toEnvelope(elements, meta)
	default:
		envelope = c.toEnvelope([]interface{}{qr.Result}, meta)
	}

	resp := NewWSRestResponse()

	resp.WriteHeader(http.StatusOK)

	producer := runtime.JSONProducer()

	err = producer.Produce(resp, envelope)

	c.logger.Debugf("resp: %v", resp)

	return resp

}

func (c *WSConnection) handleSessions(rc *response.RequestContext, queryParams string, sessionToken string, b []byte) *WSRestResponse {
	c.logger.Debug("handleSessions() entered ")

	apiSession, err := c.AppEnv.GetHandlers().ApiSession.ReadByToken(sessionToken)
	c.logger.Debugf("apiSession: %v, err: %v", apiSession, err)

	var sessionCreateBody *rest_model.SessionCreate

	// var sessionCreateParms map[string]interface{}
	err = json.Unmarshal(b, &sessionCreateBody)
	if err != nil {
		// 	// rc.RespondWithError(err)
		// 	// return
	}
	c.logger.Debugf("sessionCreateBody: %v", sessionCreateBody)

	sess, err := c.AppEnv.Handlers.Session.Create(routes.MapCreateSessionToModel(apiSession.Id, sessionCreateBody))
	c.logger.Debugf("sess: %v, err: %v", sess, err)

	modelSession, err := c.AppEnv.GetHandlers().Session.Read(sess)
	if err != nil {
		// nsr.RespondWithError(err)
		// return
	}
	restModel, err := routes.MapSessionToRestModel(c.AppEnv, modelSession)
	if err != nil {
		// nsr.RespondWithError(err)
		// return
	}
	newSessionEnvelope := &rest_model.SessionCreateEnvelope{
		Data: restModel,
		Meta: &rest_model.Meta{},
	}

	resp := NewWSRestResponse()

	resp.WriteHeader(http.StatusCreated)

	producer := runtime.JSONProducer()

	err = producer.Produce(resp, newSessionEnvelope)

	c.logger.Debugf("resp: %v", resp)

	return resp

}

func (c *WSConnection) toEnvelope(data []interface{}, meta *rest_model.Meta) interface{} {
	return rest_model.Empty{
		Data: data,
		Meta: meta,
	}
}

func (c *WSConnection) requestHandler() {
	wsListener := channel2.NewWSListener(c)

	for {
		msg, err := wsListener.Impl.Rx()
		if err != nil {
			c.logger.Error(err)
			_ = c.Close()
			break
		}
		c.logger.Debug("Recv: ", string(msg.Body))

		/**
		 *	Here's samples of what we support at the moment
		 */
		// {"method":"GET", "path":"/version","queryParams":null,"headers":{"Accept":["application/json"],"Content-Type":["application/json"]}}
		// {"method":"POST","path":"/authenticate","queryParams":"method=cert","headers":{"Accept":["application/json"],"Content-Type":["application/json"]},"body":{"configTypes":["ziti-tunneler-client.v1"]}}
		// {"method":"GET", "path":"/services","queryParams":"limit=100","headers":{"zt-session":"94b70f32-62c4-409a-9e97-32ad73bd2750","Accept":["application/json"],"Content-Type":["application/json"]}}
		// {"method":"POST","path":"/sessions","queryParams":null,"headers":{"zt-session":"9dfc2779-5889-49bd-a9d6-1c69cb9d92ed","Accept":["application/json"],"Content-Type":["application/json"]},"body":{"serviceId":"8jbSUFpMg"}}

		m, _, _, err := jsonparser.Get(msg.Body, "method")
		method := string(m)
		c.logger.Debug("method: ", method)

		p, _, _, err := jsonparser.Get(msg.Body, "path")
		path := string(p)
		c.logger.Debug("path: ", path)

		q, _, _, err := jsonparser.Get(msg.Body, "queryParams")
		queryParams := string(q)
		c.logger.Debug("queryParams: ", queryParams)

		h, _, _, err := jsonparser.Get(msg.Body, "headers")
		headers := string(h)
		c.logger.Debug("headers: ", headers)

		zts, _, _, err := jsonparser.Get(msg.Body, "headers", "zt-session")
		ztSession := string(zts)
		c.logger.Debug("ztSession: ", ztSession)

		b, _, _, err := jsonparser.Get(msg.Body, "body")
		body := string(b)
		c.logger.Debug("body: ", body)

		var resp *WSRestResponse
		var respBody []byte

		rc := &response.RequestContext{
			Id:                "",
			Body:              nil,
			Identity:          nil,
			ApiSession:        nil,
			ActivePermissions: []string{},
			ResponseWriter:    nil,
			Request:           nil,
			EventLogger:       nil,
		}

		rc.ApiSession, err = c.AppEnv.GetHandlers().ApiSession.ReadByToken(ztSession)
		if err != nil {
			c.logger.WithError(err).Debugf("looking up API session for %s resulted in an error, request will continue unauthenticated", rc.SessionToken)
			rc.ApiSession = nil
			rc.SessionToken = ""
		}

		if rc.ApiSession != nil {
			var err error
			rc.Identity, err = c.AppEnv.GetHandlers().Identity.Read(rc.ApiSession.IdentityId)
			if err != nil {
				// if boltz.IsErrNotFoundErr(err) {
				// 	apiErr := apierror.NewUnauthorized()
				// 	apiErr.Cause = fmt.Errorf("associated identity %s not found", rc.ApiSession.IdentityId)
				// 	apiErr.AppendCause = true
				// 	return apiErr
				// } else {
				// 	return err
				// }
			}
		}

		if rc.Identity != nil {
			rc.ActivePermissions = append(rc.ActivePermissions, permissions.AuthenticatedPermission)

			if rc.Identity.IsAdmin {
				rc.ActivePermissions = append(rc.ActivePermissions, permissions.AdminPermission)
			}
		}

		// requestContext.Responder = response.NewResponder(requestContext)

		switch path {

		case "/version":
			c.handleVersion(method, path, queryParams, body)

		case "/authenticate":
			resp = c.handleAuthenticate(rc, b)

		case "/services":
			resp = c.handleServices(rc, queryParams, ztSession, b)

		case "/sessions":
			resp = c.handleSessions(rc, queryParams, ztSession, b)

		default:
			panic("unknown path")
		}

		c.logger.Debugf("resp: %v", resp)
		if resp != nil && resp.Body != nil {
			respBody = resp.Body
			c.logger.Debugf("resp body: %v", string(resp.Body))
		}

		err = wsListener.Respond(msg, true, respBody)
		if err != nil {
			c.logger.Error(err)
			_ = c.Close()
			break
		}
		c.logger.Debug("Response sent")

	}
}

// tlsHandshake wraps the websocket in a TLS server.
func (c *WSConnection) tlsHandshake() error {
	c.logger.Debug("TLS Handshake initiated with client at: ", c.RemoteAddr())

	var err error
	var serverCertPEM []byte
	var keyPEM []byte

	if serverCertPEM, err = ioutil.ReadFile(c.config.WSApi.IdentityConfig.ServerCert); err != nil {
		c.logger.Error(err)
		_ = c.Close()
		return err
	}
	if keyPEM, err = ioutil.ReadFile(c.config.WSApi.IdentityConfig.ServerKey); err != nil {
		c.logger.Error(err)
		_ = c.Close()
		return err
	}

	cert, err := tls.X509KeyPair(serverCertPEM, keyPEM)
	if err != nil {
		c.logger.Error(err)
		_ = c.Close()
		return err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(serverCertPEM)

	cfg := &tls.Config{
		ClientCAs:    caCertPool,
		Certificates: []tls.Certificate{cert},
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		ClientAuth:                  tls.RequireAndVerifyClientCert,
		MinVersion:                  tls.VersionTLS11,
		PreferServerCipherSuites:    true,
		DynamicRecordSizingDisabled: true,
	}

	c.tlsConn = tls.Server(c, cfg)
	if err = c.tlsConn.Handshake(); err != nil {
		c.logger.Error(err)
		c.logger.Error("TLS Handshake failed with client at: ", c.RemoteAddr())
		_ = c.Close()
		return err
	}

	c.tlsConnHandshakeComplete = true

	c.logger.Debug("TLS Handshake completed successfully with client at: ", c.RemoteAddr())

	return nil
}

// newSafeBuffer instantiates a new safeBuffer
func newSafeBuffer(log *logrus.Entry) *safeBuffer {
	return &safeBuffer{
		buf: bytes.NewBuffer(nil),
		log: log,
	}
}

func (self *WSConnection) PeerCertificates() []*x509.Certificate {
	if self.tlsConnHandshakeComplete {
		return self.tlsConn.ConnectionState().PeerCertificates
	} else {
		return nil
	}
}

func (self *WSConnection) Reader() io.Reader {
	return self
}

func (self *WSConnection) Writer() io.Writer {
	return self
}

func (self *WSConnection) Conn() net.Conn {
	return self.tlsConn // Obtain the TLS connection that wraps the websocket
}

func (self *WSConnection) Detail() *transport.ConnectionDetail {
	return nil
}

func (self *WSConnection) SetReadTimeout(t time.Duration) error {
	return self.ws.UnderlyingConn().SetReadDeadline(time.Now().Add(t))
}

func (self *WSConnection) SetWriteTimeout(t time.Duration) error {
	return self.ws.UnderlyingConn().SetWriteDeadline(time.Now().Add(t))
}

// ClearReadTimeout clears the read time for all current and future reads
//
func (self *WSConnection) ClearReadTimeout() error {
	var zero time.Time
	return self.ws.UnderlyingConn().SetReadDeadline(zero)
}

// ClearWriteTimeout clears the write timeout for all current and future writes
//
func (self *WSConnection) ClearWriteTimeout() error {
	var zero time.Time
	return self.ws.UnderlyingConn().SetWriteDeadline(zero)
}

func (self *WSConnection) LocalAddr() net.Addr {
	return self.ws.UnderlyingConn().LocalAddr()
}
func (self *WSConnection) RemoteAddr() net.Addr {
	return self.ws.UnderlyingConn().RemoteAddr()
}
func (self *WSConnection) SetDeadline(t time.Time) error {
	return self.ws.UnderlyingConn().SetDeadline(t)
}
func (self *WSConnection) SetReadDeadline(t time.Time) error {
	return self.ws.UnderlyingConn().SetReadDeadline(t)
}
func (self *WSConnection) SetWriteDeadline(t time.Time) error {
	return self.ws.UnderlyingConn().SetWriteDeadline(t)
}
