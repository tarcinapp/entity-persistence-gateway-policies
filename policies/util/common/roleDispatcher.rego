package policies.util.common.roleDispatcher

# Purpose: To route role checks to the appropriate Role Utility file
import data.policies.util.entities.roles as entities_roles
import data.policies.util.entityReactions.roles as entity_reactions_roles
import data.policies.util.listReactions.roles as list_reactions_roles
import data.policies.util.lists.roles as lists_roles
import data.policies.util.relations.roles as relations_roles

# get_effective_role(recordType, operation, source_object)
#
# Purpose: To find the user's highest privileged role (Effective Role)
# in the context of the given recordType and source_object (for kind detection).
#
# Hierarchy: Admin > Editor > Member > Visitor
#
# Input:
#   - recordType: "entities", "lists", "relations", etc.
#   - operation: "find", "create", "update", etc.
#   - source_object: requestPayload or originalRecord (for kind detection)
# Purpose: To collect all special Role Utility files here (Central Hub)

# -----------------------------------------------------------------------------
# ENTITIES
# -----------------------------------------------------------------------------
get_effective_role("entities", operation, source_object) := "admin" if {
	entities_roles.is_user_admin(operation, source_object)
}

else := "editor" if {
	get_record_type_match("entities")
	entities_roles.is_user_editor(operation, source_object)
}

else := "member" if {
	get_record_type_match("entities")
	entities_roles.is_user_member(operation, source_object)
}

else := "visitor" if {
	get_record_type_match("entities")
	entities_roles.is_user_visitor(operation, source_object)
}

# -----------------------------------------------------------------------------
# LISTS
# -----------------------------------------------------------------------------
get_effective_role("lists", operation, source_object) := "admin" if {
	lists_roles.is_user_admin(operation, source_object)
}

else := "editor" if {
	get_record_type_match("lists")
	lists_roles.is_user_editor(operation, source_object)
}

else := "member" if {
	get_record_type_match("lists")
	lists_roles.is_user_member(operation, source_object)
}

else := "visitor" if {
	get_record_type_match("lists")
	lists_roles.is_user_visitor(operation, source_object)
}

# -----------------------------------------------------------------------------
# RELATIONS
# -----------------------------------------------------------------------------
get_effective_role("relations", operation, source_object) := "admin" if {
	relations_roles.is_user_admin(operation, source_object)
}

else := "editor" if {
	get_record_type_match("relations")
	relations_roles.is_user_editor(operation, source_object)
}

else := "member" if {
	get_record_type_match("relations")
	relations_roles.is_user_member(operation, source_object)
}

else := "visitor" if {
	get_record_type_match("relations")
	relations_roles.is_user_visitor(operation, source_object)
}

# -----------------------------------------------------------------------------
# ENTITY REACTIONS
# -----------------------------------------------------------------------------
get_effective_role("entityReactions", operation, source_object) := "admin" if {
	entity_reactions_roles.is_user_admin(operation, source_object)
}

else := "editor" if {
	get_record_type_match("entityReactions")
	entity_reactions_roles.is_user_editor(operation, source_object)
}

else := "member" if {
	get_record_type_match("entityReactions")
	entity_reactions_roles.is_user_member(operation, source_object)
}

else := "visitor" if {
	get_record_type_match("entityReactions")
	entity_reactions_roles.is_user_visitor(operation, source_object)
}

# -----------------------------------------------------------------------------
# LIST REACTIONS
# -----------------------------------------------------------------------------
get_effective_role("listReactions", operation, source_object) := "admin" if {
	list_reactions_roles.is_user_admin(operation, source_object)
}

else := "editor" if {
	get_record_type_match("listReactions")
	list_reactions_roles.is_user_editor(operation, source_object)
}

else := "member" if {
	get_record_type_match("listReactions")
	list_reactions_roles.is_user_member(operation, source_object)
}

else := "visitor" if {
	get_record_type_match("listReactions")
	list_reactions_roles.is_user_visitor(operation, source_object)
}

# Helper: Sadece kod tekrarını azaltmak ve okunabilirliği artırmak için
# "Switch-Case" mantığının doğru çalıştığından emin olmak için kullanılır.
get_record_type_match(rt) if {
	rt != null
}
