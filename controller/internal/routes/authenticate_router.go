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

package routes

import (
	"github.com/go-openapi/runtime/middleware"
	"github.com/google/uuid"
	"github.com/michaelquigley/pfxlog"
	"github.com/mitchellh/mapstructure"
	"github.com/openziti/edge/controller/apierror"
	"github.com/openziti/edge/controller/env"
	"github.com/openziti/edge/controller/internal/permissions"
	"github.com/openziti/edge/controller/model"
	"github.com/openziti/edge/controller/response"
	"github.com/openziti/edge/rest_model"
	"github.com/openziti/edge/rest_server/operations/authentication"
	"github.com/openziti/foundation/metrics"
	"github.com/openziti/foundation/util/stringz"
	"net"
	"net/http"
	"time"
)

func init() {
	r := NewAuthRouter()
	env.AddRouter(r)
}

type AuthRouter struct {
	createTimer metrics.Timer
}

func NewAuthRouter() *AuthRouter {
	return &AuthRouter{}
}

func (ro *AuthRouter) Register(ae *env.AppEnv) {
	ro.createTimer = ae.GetHostController().GetNetwork().GetMetricsRegistry().Timer("api-session.create")
	ae.Api.AuthenticationAuthenticateHandler = authentication.AuthenticateHandlerFunc(func(params authentication.AuthenticateParams) middleware.Responder {
		return ae.IsAllowed(func(ae *env.AppEnv, rc *response.RequestContext) { ro.authHandler(ae, rc, params) }, params.HTTPRequest, "", "", permissions.Always())
	})

	ae.Api.AuthenticationAuthenticateMfaHandler = authentication.AuthenticateMfaHandlerFunc(func(params authentication.AuthenticateMfaParams, i interface{}) middleware.Responder {
		return ae.IsAllowed(func(ae *env.AppEnv, rc *response.RequestContext) { ro.authMfa(ae, rc, params) }, params.HTTPRequest, "", "", permissions.IsPartiallyAuthenticated())
	})
}

func (ro *AuthRouter) authHandler(ae *env.AppEnv, rc *response.RequestContext, params authentication.AuthenticateParams) {
	start := time.Now()
	logger := pfxlog.Logger()
	authContext := model.NewAuthContextHttp(params.HTTPRequest, params.Method, params.Auth)

	identity, err := ae.Handlers.Authenticator.IsAuthorized(authContext)

	if err != nil {
		rc.RespondWithError(err)
		return
	}

	if identity == nil {
		rc.RespondWithApiError(apierror.NewUnauthorized())
		return
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
					logger.WithError(err).Error("error processing env info")
				}
				shouldUpdate = true
			}
		}

		if sdkInfoInterface := dataMap["sdkInfo"]; sdkInfoInterface != nil {
			if sdkInfo := sdkInfoInterface.(map[string]interface{}); sdkInfo != nil {
				if err := mapstructure.Decode(sdkInfo, &identity.SdkInfo); err != nil {
					logger.WithError(err).Error("error processing sdk info")
				}
				shouldUpdate = true
			}
		}

		if shouldUpdate {
			if err := ae.GetHandlers().Identity.PatchInfo(identity); err != nil {
				logger.WithError(err).Errorf("failed to update sdk/env info on identity [%s] auth", identity.Id)
			}
		}
	}

	token := uuid.New().String()
	configTypes := map[string]struct{}{}

	if params.Auth != nil {
		configTypes = mapConfigTypeNamesToIds(ae, params.Auth.ConfigTypes, identity.Id)
	}
	remoteIpStr := ""
	if remoteIp, _, err := net.SplitHostPort(rc.Request.RemoteAddr); err == nil {
		remoteIpStr = remoteIp
	}

	logger.Debugf("client %v requesting configTypes: %v", identity.Name, configTypes)
	newApiSession := &model.ApiSession{
		IdentityId:  identity.Id,
		Token:       token,
		ConfigTypes: configTypes,
		IPAddress:   remoteIpStr,
	}

	mfa, err := ae.Handlers.Mfa.ReadByIdentityId(identity.Id)

	if err != nil {
		rc.RespondWithError(err)
		return
	}

	if mfa != nil && mfa.IsVerified {
		newApiSession.MfaRequired = true
		newApiSession.MfaComplete = false
	}

	sessionId, err := ae.Handlers.ApiSession.Create(newApiSession)

	if err != nil {
		rc.RespondWithError(err)
		return
	}

	filledApiSession, err := ae.Handlers.ApiSession.Read(sessionId)

	if err != nil {
		logger.WithField("cause", err).Error("loading session by id resulted in an error")
		rc.RespondWithApiError(apierror.NewUnauthorized())
	}

	apiSession := MapToCurrentApiSessionRestModel(filledApiSession, ae.Config.SessionTimeoutDuration())
	rc.ApiSession = filledApiSession

	//re-calc session headers as they were not set wwhen ApiSession == NIL
	response.AddSessionHeaders(rc)

	envelope := &rest_model.CurrentAPISessionDetailEnvelope{Data: apiSession, Meta: &rest_model.Meta{}}

	expiration := time.Time(*apiSession.ExpiresAt)
	cookie := http.Cookie{Name: ae.AuthCookieName, Value: token, Expires: expiration}

	rc.ResponseWriter.Header().Set(ae.AuthHeaderName, filledApiSession.Token)
	http.SetCookie(rc.ResponseWriter, &cookie)
	ro.createTimer.UpdateSince(start)

	rc.Respond(envelope, http.StatusOK)
}

func (ro *AuthRouter) authMfa(ae *env.AppEnv, rc *response.RequestContext, params authentication.AuthenticateMfaParams) {
	mfa, err := ae.Handlers.Mfa.ReadByIdentityId(rc.Identity.Id)

	if err != nil {
		rc.RespondWithError(err)
		return
	}

	if mfa == nil {
		rc.RespondWithError(apierror.NewMfaNotEnrolledError())
		return
	}

	ok, _ := ae.Handlers.Mfa.Verify(mfa, *params.MfaAuth.Code)

	if !ok {
		rc.RespondWithError(apierror.NewInvalidMfaTokenError())
		return
	}

	if err := ae.Handlers.ApiSession.MfaCompleted(rc.ApiSession); err != nil {
		rc.RespondWithError(err)
		return
	}

	postureResponse := &model.PostureResponse{
		PostureCheckId: model.MfaProviderZiti,
		TypeId:         "MFA",
		TimedOut:       false,
		LastUpdatedAt:  time.Now(),
	}

	postureSubType := &model.PostureResponseMfa{
		ApiSessionId: rc.ApiSession.Id,
		PassedMfa:    true,
	}

	postureResponse.SubType = postureSubType
	postureSubType.PostureResponse = postureResponse

	ae.Handlers.PostureResponse.Create(rc.Identity.Id, []*model.PostureResponse{postureResponse})

	rc.RespondWithEmptyOk()
}

func mapConfigTypeNamesToIds(ae *env.AppEnv, values []string, identityId string) map[string]struct{} {
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
				pfxlog.Logger().Debugf("user %v submitted %v as a config type of interest, but no matching records found", identityId, val)
			}
		}
	}
	return stringz.SliceToSet(result)
}
