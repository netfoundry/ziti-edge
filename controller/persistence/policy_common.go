package persistence

import (
	"bytes"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/storage/ast"
	"github.com/openziti/foundation/storage/boltz"
	"github.com/openziti/foundation/util/errorz"
	"github.com/openziti/foundation/util/stringz"
	"github.com/pkg/errors"
	"go.etcd.io/bbolt"
	"strings"
)

type serviceEventHandler struct {
	events []*ServiceEvent
}

func (self *serviceEventHandler) addServiceUpdatedEvent(store *baseStore, tx *bbolt.Tx, serviceId []byte) {
	cursor := store.stores.edgeService.bindIdentitiesCollection.IterateLinks(tx, serviceId)

	for cursor != nil && cursor.IsValid() {
		self.addServiceEvent(tx, cursor.Current(), serviceId, ServiceUpdated)
		cursor.Next()
	}

	cursor = store.stores.edgeService.dialIdentitiesCollection.IterateLinks(tx, serviceId)
	for cursor != nil && cursor.IsValid() {
		self.addServiceEvent(tx, cursor.Current(), serviceId, ServiceUpdated)
		cursor.Next()
	}
}

func (self *serviceEventHandler) addServiceEvent(tx *bbolt.Tx, identityId, serviceId []byte, eventType ServiceEventType) {
	if len(self.events) == 0 {
		tx.OnCommit(func() {
			ServiceEvents.dispatchEventsAsync(self.events)
		})
	}

	self.events = append(self.events, &ServiceEvent{
		Type:       eventType,
		IdentityId: string(identityId),
		ServiceId:  string(serviceId),
	})
}

type roleAttributeChangeContext struct {
	serviceEventHandler
	tx                    *bbolt.Tx
	rolesSymbol           boltz.EntitySetSymbol
	linkCollection        boltz.LinkCollection
	relatedLinkCollection boltz.LinkCollection
	denormLinkCollection  boltz.RefCountedLinkCollection
	changeHandler         func(fromId, toId []byte, add bool)
	errorz.ErrorHolder
}

func (self *roleAttributeChangeContext) addServicePolicyEvent(identityId, serviceId []byte, policyType PolicyType, add bool) {
	var eventType ServiceEventType
	if add {
		if policyType == PolicyTypeDial {
			eventType = ServiceDialAccessGained
		}
		if policyType == PolicyTypeBind {
			eventType = ServiceBindAccessGained
		}
	} else {
		if policyType == PolicyTypeDial {
			eventType = ServiceDialAccessLost
		}
		if policyType == PolicyTypeBind {
			eventType = ServiceBindAccessLost
		}
	}

	self.addServiceEvent(self.tx, identityId, serviceId, eventType)
}

func (store *baseStore) updateServicePolicyRelatedRoles(ctx *roleAttributeChangeContext, entityId []byte, newRoleAttributes []boltz.FieldTypeAndValue) {
	cursor := ctx.rolesSymbol.GetStore().IterateIds(ctx.tx, ast.BoolNodeTrue)

	entityRoles := FieldValuesToIds(newRoleAttributes)

	semanticSymbol := store.stores.servicePolicy.symbolSemantic
	policyTypeSymbol := store.stores.servicePolicy.symbolPolicyType

	isServices := ctx.rolesSymbol == store.stores.servicePolicy.symbolServiceRoles
	isIdentity := ctx.rolesSymbol == store.stores.servicePolicy.symbolIdentityRoles

	for ; cursor.IsValid(); cursor.Next() {
		policyId := cursor.Current()
		roleSet := ctx.rolesSymbol.EvalStringList(ctx.tx, policyId)
		roles, ids, err := splitRolesAndIds(roleSet)
		if err != nil {
			ctx.SetError(err)
			return
		}

		semantic := SemanticAllOf
		if _, semanticValue := semanticSymbol.Eval(ctx.tx, policyId); semanticValue != nil {
			semantic = string(semanticValue)
		}
		policyType := PolicyTypeDial
		if fieldType, policyTypeValue := policyTypeSymbol.Eval(ctx.tx, policyId); fieldType == boltz.TypeInt32 {
			policyType = PolicyType(*boltz.BytesToInt32(policyTypeValue))
		}
		if policyType == PolicyTypeDial {
			if isServices {
				ctx.denormLinkCollection = store.stores.edgeService.dialIdentitiesCollection
				ctx.changeHandler = func(fromId, toId []byte, add bool) {
					ctx.addServicePolicyEvent(toId, fromId, PolicyTypeDial, add)
				}
			} else if isIdentity {
				ctx.denormLinkCollection = store.stores.identity.dialServicesCollection
				ctx.changeHandler = func(fromId, toId []byte, add bool) {
					ctx.addServicePolicyEvent(fromId, toId, PolicyTypeDial, add)
				}
			} else {
				ctx.denormLinkCollection = store.stores.postureCheck.dialServicesCollection
				ctx.changeHandler = func(fromId, toId []byte, add bool) {
					pfxlog.Logger().Warnf("posture check %v -> service %v - included? %v", string(fromId), string(toId), add)
					ctx.addServiceUpdatedEvent(store, ctx.tx, toId)
				}
			}
		} else if isServices {
			ctx.denormLinkCollection = store.stores.edgeService.bindIdentitiesCollection
			ctx.changeHandler = func(fromId, toId []byte, add bool) {
				ctx.addServicePolicyEvent(toId, fromId, PolicyTypeBind, add)
			}
		} else if isIdentity {
			ctx.denormLinkCollection = store.stores.identity.bindServicesCollection
			ctx.changeHandler = func(fromId, toId []byte, add bool) {
				ctx.addServicePolicyEvent(fromId, toId, PolicyTypeBind, add)
			}
		} else {
			ctx.denormLinkCollection = store.stores.postureCheck.bindServicesCollection
			ctx.changeHandler = func(fromId, toId []byte, add bool) {
				pfxlog.Logger().Warnf("posture check %v -> service %v - included? %v", string(fromId), string(toId), add)
				ctx.addServiceUpdatedEvent(store, ctx.tx, toId)
			}
		}
		evaluatePolicyAgainstEntity(ctx, semantic, entityId, policyId, ids, roles, entityRoles)
	}
}

func EvaluatePolicy(ctx *roleAttributeChangeContext, policy Policy, roleAttributesSymbol boltz.EntitySetSymbol) {
	policyId := []byte(policy.GetId())

	roleSet := ctx.rolesSymbol.EvalStringList(ctx.tx, policyId)
	roles, ids, err := splitRolesAndIds(roleSet)
	if err != nil {
		ctx.SetError(err)
		return
	}

	if err := validateEntityIds(ctx.tx, ctx.linkCollection.GetLinkedSymbol().GetStore(), ctx.rolesSymbol.GetName(), ids); err != nil {
		ctx.SetError(err)
		return
	}

	cursor := roleAttributesSymbol.GetStore().IterateIds(ctx.tx, ast.BoolNodeTrue)
	for ; cursor.IsValid(); cursor.Next() {
		entityId := cursor.Current()
		entityRoleAttributes := roleAttributesSymbol.EvalStringList(ctx.tx, entityId)
		evaluatePolicyAgainstEntity(ctx, policy.GetSemantic(), entityId, policyId, ids, roles, entityRoleAttributes)
	}
}

func validateEntityIds(tx *bbolt.Tx, store boltz.ListStore, field string, ids []string) error {
	var invalid []string
	for _, val := range ids {
		if !store.IsEntityPresent(tx, val) {
			invalid = append(invalid, val)
		}
	}
	if len(invalid) > 0 {
		return errorz.NewFieldError(fmt.Sprintf("no %v found with the given ids", store.GetEntityType()), field, invalid)
	}
	return nil
}

func UpdateRelatedRoles(ctx *roleAttributeChangeContext, entityId []byte, newRoleAttributes []boltz.FieldTypeAndValue, semanticSymbol boltz.EntitySymbol) {
	cursor := ctx.rolesSymbol.GetStore().IterateIds(ctx.tx, ast.BoolNodeTrue)

	entityRoles := FieldValuesToIds(newRoleAttributes)

	for ; cursor.IsValid(); cursor.Next() {
		policyId := cursor.Current()
		roleSet := ctx.rolesSymbol.EvalStringList(ctx.tx, policyId)
		roles, ids, err := splitRolesAndIds(roleSet)
		if err != nil {
			ctx.SetError(err)
			return
		}

		semantic := SemanticAllOf
		if _, semanticValue := semanticSymbol.Eval(ctx.tx, policyId); semanticValue != nil {
			semantic = string(semanticValue)
		}
		evaluatePolicyAgainstEntity(ctx, semantic, entityId, policyId, ids, roles, entityRoles)
	}
}

func evaluatePolicyAgainstEntity(ctx *roleAttributeChangeContext, semantic string, entityId, policyId []byte, ids, roles, roleAttributes []string) {
	if stringz.Contains(ids, string(entityId)) || stringz.Contains(roles, "all") ||
		(strings.EqualFold(semantic, SemanticAllOf) && len(roles) > 0 && stringz.ContainsAll(roleAttributes, roles...)) ||
		(strings.EqualFold(semantic, SemanticAnyOf) && len(roles) > 0 && stringz.ContainsAny(roleAttributes, roles...)) {
		ProcessEntityPolicyMatched(ctx, entityId, policyId)
	} else {
		ProcessEntityPolicyUnmatched(ctx, entityId, policyId)
	}
}

func ProcessEntityPolicyMatched(ctx *roleAttributeChangeContext, entityId, policyId []byte) {
	if added, err := ctx.linkCollection.AddLink(ctx.tx, policyId, entityId); ctx.SetError(err) || !added {
		return
	}
	cursor := ctx.relatedLinkCollection.IterateLinks(ctx.tx, policyId)
	for ; cursor.IsValid(); cursor.Next() {
		relatedEntityId := cursor.Current()
		newCount, err := ctx.denormLinkCollection.IncrementLinkCount(ctx.tx, entityId, relatedEntityId)
		if ctx.SetError(err) {
			return
		}
		if ctx.changeHandler != nil && newCount == 1 {
			ctx.changeHandler(entityId, relatedEntityId, true)
		}
	}
}

func ProcessEntityPolicyUnmatched(ctx *roleAttributeChangeContext, entityId, policyId []byte) {
	if removed, err := ctx.linkCollection.RemoveLink(ctx.tx, policyId, entityId); ctx.SetError(err) || !removed {
		return
	}

	cursor := ctx.relatedLinkCollection.IterateLinks(ctx.tx, policyId)
	for ; cursor.IsValid(); cursor.Next() {
		relatedEntityId := cursor.Current()
		newCount, err := ctx.denormLinkCollection.DecrementLinkCount(ctx.tx, entityId, relatedEntityId)
		if ctx.SetError(err) {
			return
		}
		if ctx.changeHandler != nil && newCount == 0 {
			ctx.changeHandler(entityId, relatedEntityId, false)
		}
	}
}

type denormCheckCtx struct {
	name                   string
	tx                     *bbolt.Tx
	sourceStore            boltz.CrudStore
	targetStore            boltz.CrudStore
	policyStore            boltz.CrudStore
	sourceCollection       boltz.LinkCollection
	targetCollection       boltz.LinkCollection
	targetDenormCollection boltz.RefCountedLinkCollection
	policyFilter           func(policyId []byte) bool
	errorSink              func(err error, fixed bool)
	repair                 bool
}

func validatePolicyDenormalization(ctx *denormCheckCtx) error {
	for sourceCursor := ctx.sourceStore.IterateIds(ctx.tx, ast.BoolNodeTrue); sourceCursor.IsValid(); sourceCursor.Next() {
		sourceEntityId := sourceCursor.Current()
		for targetCursor := ctx.targetStore.IterateIds(ctx.tx, ast.BoolNodeTrue); targetCursor.IsValid(); targetCursor.Next() {
			targetEntityId := targetCursor.Current()

			var relatedPolicies []string

			for policyCursor := ctx.policyStore.IterateIds(ctx.tx, ast.BoolNodeTrue); policyCursor.IsValid(); policyCursor.Next() {
				policyId := policyCursor.Current()
				if ctx.policyFilter == nil || ctx.policyFilter(policyId) {
					sourceRelated := isRelatedByLinkCollection(ctx.tx, ctx.sourceCollection, policyId, sourceEntityId)
					targetRelated := isRelatedByLinkCollection(ctx.tx, ctx.targetCollection, policyId, targetEntityId)
					if sourceRelated && targetRelated {
						relatedPolicies = append(relatedPolicies, string(policyId))
					}
				}
			}
			linkCount := len(relatedPolicies)
			var sourceLinkCount, targetLinkCount *int32
			var err error
			if ctx.repair {
				sourceLinkCount, targetLinkCount, err = ctx.targetDenormCollection.SetLinkCount(ctx.tx, sourceEntityId, targetEntityId, linkCount)
			} else {
				sourceLinkCount, targetLinkCount = ctx.targetDenormCollection.GetLinkCounts(ctx.tx, sourceEntityId, targetEntityId)
			}
			if err != nil {
				return err
			}
			logDiscrepencies(ctx, linkCount, sourceEntityId, targetEntityId, sourceLinkCount, targetLinkCount)
		}
	}
	return nil
}

func logDiscrepencies(ctx *denormCheckCtx, count int, sourceId, targetId []byte, sourceLinkCount, targetLinkCount *int32) {
	oldValuesMatch := (sourceLinkCount == nil && targetLinkCount == nil) || (sourceLinkCount != nil && targetLinkCount != nil && *sourceLinkCount == *targetLinkCount)
	if !oldValuesMatch {
		err := errors.Errorf("%v: ismatched link counts. %v %v (%v) <-> %v %v (%v), should be both are %v", ctx.name,
			ctx.sourceStore.GetSingularEntityType(), string(sourceId), sourceLinkCount,
			ctx.targetStore.GetSingularEntityType(), string(targetId), targetLinkCount, count)
		ctx.errorSink(err, ctx.repair)
	}

	if ((sourceLinkCount == nil || *sourceLinkCount == 0) && count != 0) ||
		(sourceLinkCount != nil && *sourceLinkCount != int32(count)) {
		sourceCount := int32(0)
		if sourceLinkCount != nil {
			sourceCount = *sourceLinkCount
		}
		err := errors.Errorf("%v: incorrect link counts for %v %v <-> %v %v is %v, should be %v", ctx.name,
			ctx.sourceStore.GetSingularEntityType(), string(sourceId),
			ctx.targetStore.GetSingularEntityType(), string(targetId),
			sourceCount, count)
		ctx.errorSink(err, ctx.repair)
	}
}

func isRelatedByLinkCollection(tx *bbolt.Tx, linkCollection boltz.LinkCollection, entityId, relatedId []byte) bool {
	cursor := linkCollection.IterateLinks(tx, entityId)
	cursor.Seek(relatedId)
	return bytes.Equal(cursor.Current(), relatedId)
}
