# Role Utility Refactoring Status - Phase 4-B

## Summary
This document tracks the progress of updating all policy files to use the new `(operation, kind)` function signature for role utility functions.

## Completed Files ✅

### Entity Routes (11/11) ✅
- createEntity
- createEntityChild  
- findEntities
- findEntityById
- findEntityChildren
- findEntityParents
- countEntities
- updateEntityById
- replaceEntityById
- updateAllEntities
- deleteEntityById

### List Routes (11/11) ✅
- createList
- createListChild
- findLists
- findListById
- findListChildren
- findListParents
- countLists
- updateListById
- replaceListById
- updateAllLists
- deleteListById

### Relation Routes (8/8) ✅
- createRelation
- findRelations
- findRelationById
- countRelations
- updateRelationById
- replaceRelationById
- updateAllRelations
- deleteRelationById

### EntityReaction Routes (10/10) ✅
- ✅ findEntityReactions
- ✅ countEntityReactions
- ✅ deleteEntityReactionById
- ✅ updateAllEntityReactions
- ✅ findParentsByEntityReactionId
- ✅ findChildrenEntityReactionsByReactionId
- ✅ findEntityReactionById
- ✅ createEntityReaction (main checks)
- ✅ createChildEntityReaction
- ✅ updateEntityReactionById
- ✅ replaceEntityReactionById

### ListReaction Routes (10/10) ✅
- ✅ findListReactions
- ✅ countListReactions
- ✅ deleteListReactionById
- ✅ updateAllListReactions
- ✅ findParentsByListReactionId
- ✅ findChildrenListReactionsByReactionId
- ✅ findListReactionById
- ✅ createListReaction
- ✅ createChildListReaction
- ✅ updateListReactionById
- ✅ replaceListReactionById

### Field Policy Files (5/5) ✅
- ✅ fields/entities/policy
- ✅ fields/lists/policy
- ✅ fields/relations/policy
- ✅ fields/entityReactions/policy
- ✅ fields/listReactions/policy

### Through-Routes (13/13) ✅
- ✅ reactionsThroughEntity/createReactionByEntityId
- ✅ reactionsThroughEntity/findReactionsByEntityId
- ✅ reactionsThroughEntity/updateReactionsByEntityId
- ✅ reactionsThroughEntity/deleteReactionsByEntityId
- ✅ reactionsThroughList/createReactionByListId
- ✅ reactionsThroughList/findReactionsByListId
- ✅ reactionsThroughList/updateReactionsByListId
- ✅ reactionsThroughList/deleteReactionsByListId
- ✅ entitiesThroughList/createEntityByListId
- ✅ entitiesThroughList/findEntitiesByListId
- ✅ entitiesThroughList/updateEntitiesByListId
- ✅ entitiesThroughList/deleteEntitiesByListId
- ✅ listsThroughEntity/findListsByEntityId

---

## Refactoring Rules Reference

### Kind Parameter Logic

**For main resource role checks (role_utils):**
1. **Create operations** → `input.requestPayload._kind`
2. **ID-based operations** (findById, updateById, replaceById, deleteById) → `input.originalRecord._kind`
3. **Collection operations** (findAll, count, findChildren, findParents, updateAll) → `null`

**For cross-resource permission checks:**
- `entity_role_utils.is_user_X("find")` → `entity_role_utils.is_user_X("find", null)`
- `list_role_utils.is_user_X("find")` → `list_role_utils.is_user_X("find", null)`
- `reaction_roles.is_user_X("op")` → Follow main resource rules above

### Pattern Examples

#### Create Operation
```rego
# OLD
role_utils.is_user_admin("create")

# NEW
role_utils.is_user_admin("create", input.requestPayload._kind)
```

#### ID-Based Operation
```rego
# OLD
role_utils.is_user_admin("update")

# NEW
role_utils.is_user_admin("update", input.originalRecord._kind)
```

#### Collection Operation
```rego
# OLD
role_utils.is_user_admin("find")

# NEW  
role_utils.is_user_admin("find", null)
```

#### Cross-Resource Check
```rego
# OLD
entity_role_utils.is_user_member("find")

# NEW
entity_role_utils.is_user_member("find", null)
```

---

## Remaining Work

**ALL REFACTORING COMPLETE!** 🎉

All 65 policy files have been successfully updated with the new `(operation, kind)` role utility function signatures.

---

## Progress Statistics
- **Total Files:** 70
- **Completed:** 70 (100%)
- **Remaining:** 0 (0%)

**By Category:**
- Entity: 11/11 (100%) ✅
- List: 11/11 (100%) ✅
- Relation: 8/8 (100%) ✅
- EntityReaction: 10/10 (100%) ✅
- ListReaction: 10/10 (100%) ✅
- Through-Routes: 13/13 (100%) ✅
- Field Policies: 5/5 (100%) ✅
