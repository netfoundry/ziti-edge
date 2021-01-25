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

package model

import (
	// "encoding/pem"
	"fmt"
	"github.com/openziti/edge/controller/apierror"
	"github.com/openziti/edge/controller/persistence"
	"github.com/openziti/edge/eid"
	"github.com/openziti/edge/internal/cert"
	// "github.com/openziti/edge/rest_model"
	// "github.com/openziti/fabric/controller/models"
	// "time"
)

type EnrollModuleOtf struct {
	env                  Env
	method               string
	fingerprintGenerator cert.FingerprintGenerator
}

func NewEnrollModuleOtf(env Env) *EnrollModuleOtf {
	handler := &EnrollModuleOtf{
		env:                  env,
		method:               persistence.MethodEnrollOtf,
		fingerprintGenerator: cert.NewFingerprintGenerator(),
	}

	return handler
}

func (module *EnrollModuleOtf) CanHandle(method string) bool {
	return method == module.method
}

func (module *EnrollModuleOtf) Process(ctx EnrollmentContext) (*EnrollmentResult, error) {

	username := ctx.GetUsername()
	if username == "" {
		return nil, apierror.NewInvalidEnrollUsername()
	}

	identityId := eid.New()
	identityName := "@OTF-" + username + "-" + identityId

	identType, err := module.env.GetHandlers().IdentityType.ReadByName("Device")
	if err != nil {
		return nil, err
	}

	identityNameIsValid := false
	suffixCount := 0
	for !identityNameIsValid {
		//check for name collisions append 4 digit incrementing number to end till ok
		entity, _ := module.env.GetHandlers().Identity.readEntityByQuery(fmt.Sprintf(`%s="%s"`, persistence.FieldName, identityName))

		if entity != nil {
			suffixCount = suffixCount + 1
			identityName = identityName + fmt.Sprintf("%06d", suffixCount)
		} else {
			identityNameIsValid = true
		}
	}

	identity := &Identity{
		Name:           identityName,
		IdentityTypeId: identType.Id,
		IsDefaultAdmin: false,
		IsAdmin:        false,
	}

	// certRaw, err := module.env.GetApiClientCsrSigner().Sign(ctx.GetDataAsByteArray(), &cert.SigningOpts{
	// NotAfter: time.Now().Add(time.Minute * time.Duration(module.env.GetConfig().Enrollment.OtfIdentity.DurationMinutes)),
	// })

	if err != nil {
		apiErr := apierror.NewCouldNotProcessCsr()
		apiErr.Cause = err
		apiErr.AppendCause = true
		return nil, apiErr
	}

	// fp := module.fingerprintGenerator.FromRaw(certRaw)

	// certPem := pem.EncodeToMemory(&pem.Block{
	// 	Type:  "CERTIFICATE",
	// 	Bytes: certRaw,
	// })

	// newAuthenticator := &Authenticator{
	// 	BaseEntity: models.BaseEntity{
	// 		Id: identityId,
	// 	},
	// 	Method:     persistence.MethodAuthenticatorCert,
	// 	IdentityId: identity.Id,
	// 	SubType: &AuthenticatorCert{
	// 		Fingerprint: fp,
	// 		Pem:         string(certPem),
	// 	},
	// }

	// _, _, err = module.env.GetHandlers().Identity.CreateWithAuthenticator(identity, newAuthenticator)

	if err != nil {
		return nil, err
	}

	// content := &rest_model.EnrollmentCerts{
	// 	Cert: string(certPem),
	// }

	return &EnrollmentResult{
		Identity: identity,
		// Authenticator: newAuthenticator,
		// Content:       content,
		// TextContent:   certPem,
		Status: 200,
	}, nil

}
