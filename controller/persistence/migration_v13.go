package persistence

import (
	"github.com/openziti/foundation/storage/boltz"
	log "github.com/sirupsen/logrus"
	"math"
)

func (m *Migrations) createTunnelerClientV2dot0ConfigType(step *boltz.MigrationStep) {
	configName := "ziti-tunneler-client.v2.0"
	clientConfigV2dot0TypeId := "g7cIWbcGg"
	clientConfigTypeV2dot0 := &ConfigType{
		BaseExtEntity: boltz.BaseExtEntity{Id: clientConfigV2dot0TypeId},
		Name:          configName,
		Schema: map[string]interface{}{
			"$id":                  "http://edge.openziti.org/schemas/ziti-tunneler-client.v2.0.config.json",
			"type":                 "object",
			"additionalProperties": false,
			"$defs": map[string]interface{}{
				"protocolName": map[string]interface{}{
					"type": "string",
					"enum": []interface{}{"tcp", "udp"},
				},
				"ipAddressFormat": map[string]interface{}{
					"oneOf": []interface{}{
						map[string]interface{}{"format": "ipv4"},
						map[string]interface{}{"format": "ipv6"},
					},
				},
				"ipAddress": map[string]interface{}{
					"type": "string",
					"$ref": "#/$defs/ipAddressFormat",
				},
				"cidr": map[string]interface{}{
					"type": "string",
					"oneOf": []interface{}{
						// JSON ipv4/ipv6 "format"s should work for cidrs also (see
						// https://json-schema.org/understanding-json-schema/reference/string.html),
						// but https://www.jsonschemavalidator.net disagreed, so using `pattern` instead.
						// Patterns taken from https://blog.markhatton.co.uk/2011/03/15/regular-expressions-for-ip-addresses-cidr-ranges-and-hostnames/
						map[string]interface{}{"pattern": "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/(3[0-2]|[1-2][0-9]|[0-9]))$"},
						map[string]interface{}{"pattern": "^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\\/(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))$"},
					},
				},
				"hostname": map[string]interface{}{
					"type":   "string",
					"format": "hostname",
					"not":    map[string]interface{}{"$ref": "#/$defs/ipAddressFormat"},
				},
				"address": map[string]interface{}{
					"oneOf": []interface{}{
						map[string]interface{}{"$ref": "#/$defs/ipAddress"},
						map[string]interface{}{"$ref": "#/$defs/hostname"},
						map[string]interface{}{"$ref": "#/$defs/cidr"},
					},
				},
				"portNumber": map[string]interface{}{
					"type":    "integer",
					"minimum": float64(0),
					"maximum": float64(math.MaxUint16),
				},
				"portRange": map[string]interface{}{
					"type":                 "object",
					"additionalProperties": false,
					"properties": map[string]interface{}{
						"low":  map[string]interface{}{"$ref": "#/$defs/portNumber"},
						"high": map[string]interface{}{"$ref": "#/$defs/portNumber"},
					},
				},
				"precedenceName": map[string]interface{}{
					"type": "string",
					"enum": []interface{}{"default", "required", "failed"},
				},
				"timeoutSeconds": map[string]interface{}{
					"type":    "integer",
					"minimum": float64(0),
					"maximum": float64(math.MaxInt32),
				},
				"inhabitedSet": map[string]interface{}{
					"type":        "array",
					"minItems":    1,
					"uniqueItems": true,
				},
			},
			"properties": map[string]interface{}{
				"protocol": map[string]interface{}{"$ref": "#/$defs/protocolName"},
				"protocols": map[string]interface{}{
					"allOf": []interface{}{
						map[string]interface{}{"$ref": "#/$defs/inhabitedSet"},
						map[string]interface{}{"items": map[string]interface{}{"$ref": "#/$defs/protocolName"}},
					},
				},
				"address": map[string]interface{}{"$ref": "#/$defs/address"},
				"addresses": map[string]interface{}{
					"allOf": []interface{}{
						map[string]interface{}{"$ref": "#/$defs/inhabitedSet"},
						map[string]interface{}{"items": map[string]interface{}{"$ref": "#/$defs/address"}},
					},
				},
				"port": map[string]interface{}{"$ref": "#/$defs/portNumber"},
				"ports": map[string]interface{}{
					"allOf": []interface{}{
						map[string]interface{}{"$ref": "#/$defs/inhabitedSet"},
						map[string]interface{}{"items": map[string]interface{}{"$ref": "#/$defs/portNumber"}},
					},
				},
				"portRange": map[string]interface{}{"$ref": "#/$defs/portRange"},
				"portRanges": map[string]interface{}{
					"allOf": []interface{}{
						map[string]interface{}{"$ref": "#/$defs/inhabitedSet"},
						map[string]interface{}{"items": map[string]interface{}{"$ref": "#/$defs/portRange"}},
					},
				},
				"dialOptions": map[string]interface{}{
					"type":                 "object",
					"additionalProperties": false,
					"properties": map[string]interface{}{
						"identity": map[string]interface{}{
							"type":        "string",
							"description": "Dial a terminator with the specified identity. '$intercepted_protocol', '$intercepted_ip', '$intercepted_port are resolved to the corresponding value of the intercepted address.",
						},
						"connectTimeoutSeconds": map[string]interface{}{
							"$ref":        "#/$defs/timeoutSeconds",
							"description": "defaults to 5 seconds if no dialOptions are defined. defaults to 15 if dialOptions are defined but connectTimeoutSeconds is not specified.",
						},
					},
				},
				"listenOptions": map[string]interface{}{
					"type":                 "object",
					"additionalProperties": false,
					"properties": map[string]interface{}{
						"cost": map[string]interface{}{
							"type":        "integer",
							"minimum":     0,
							"maximum":     65535,
							"description": "defaults to 0",
						},
						"precedence": map[string]interface{}{
							"$ref":        "#/$defs/precedenceName",
							"description": "defaults to 'default'",
						},
						"connectTimeoutSeconds": map[string]interface{}{
							"$ref":        "#/$defs/timeoutSeconds",
							"description": "defaults to 5",
						},
						"maxConnections": map[string]interface{}{
							"type":        "integer",
							"minimum":     1,
							"description": "defaults to 3",
						},
						"identity": map[string]interface{}{
							"type":        "string",
							"description": "Associate the hosting terminator with the specified identity. '$hosting_tunneler_id.name' resolves to the name of the hosting tunneler's identity. '$hosting_tunneler_id.tag[tagName]' resolves to the value of the 'tagName' tag on the hosting tunneler's identity.",
						},
						"bindUsingEdgeIdentity": map[string]interface{}{
							"type":        "boolean",
							"description": "Associate the hosting terminator with the name of the hosting tunneler's identity. Setting this to 'true' is equivalent to setting 'identiy=$hosting_tunneler_id.name'",
						},
					},
				},
				"sourceIp": map[string]interface{}{
					"$ref":        "#/$defs/ipAddress",
					"description": "the source address to spoof when the connection is egressed from the hosting tunneler",
				},
			},
			"allOf": []interface{}{
				map[string]interface{}{
					"anyOf": []interface{}{
						map[string]interface{}{"required": []interface{}{"protocol"}},
						map[string]interface{}{"required": []interface{}{"protocols"}},
					},
				},
				map[string]interface{}{
					"anyOf": []interface{}{
						map[string]interface{}{"required": []interface{}{"address"}},
						map[string]interface{}{"required": []interface{}{"addresses"}},
					},
				},
				map[string]interface{}{
					"anyOf": []interface{}{
						map[string]interface{}{"required": []interface{}{"port"}},
						map[string]interface{}{"required": []interface{}{"ports"}},
						map[string]interface{}{"required": []interface{}{"portRange"}},
						map[string]interface{}{"required": []interface{}{"portRanges"}},
					},
				},
			},
		},
	}

	cfg, _ := m.stores.ConfigType.LoadOneByName(step.Ctx.Tx(), configName)
	if cfg == nil {
		step.SetError(m.stores.ConfigType.Create(step.Ctx, clientConfigTypeV2dot0))
	} else {
		log.Debugf("'%s' config type already exists. not creating.", configName)
	}
}
