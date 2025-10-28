package policies.auth.routes.relations.createRelation.policy

import data.policies.util.common.verification as verification
import data.policies.util.relations.roles as role_utils
import data.policies.fields.relations.policy as forbidden_fields
import data.policies.util.common.token as token

# By default, deny requests.
default allow = false

#-----------------------------------------------

# Decide allow if any of the following section is true
#-----------------------------------------------
allow if {
	role_utils.is_user_admin("create")
	verification.is_email_verified
}

allow if {
	role_utils.is_user_editor("create")
	verification.is_email_verified
	# payload cannot contain any invalid field for the caller's role
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
}

allow if {
	role_utils.is_user_member("create")
	verification.is_email_verified
	# payload cannot contain any invalid field for the caller's role
	not payload_contains_any_field(forbidden_fields.which_fields_forbidden_for_create)
	# caller must own the referenced list
	caller_owns_referenced_list
	# referenced list must be valid/active for the creation
	referenced_list_valid_for_creation
	# caller must be able to see the target entity
	caller_can_see_target_entity
}

#-----------------------------------------------

# helpers
payload_contains_any_field(fields) if {
	some field
	field = fields[_]
	input.requestPayload[field]
}

# The caller must be listed in the referenced list's _ownerUsers OR must
# be in one of the _ownerGroups (when the list is not private). If the
# caller is a direct owner via _ownerUsers, that takes precedence.
caller_owns_referenced_list if {
	referenced_list_belong_to_user
}

caller_owns_referenced_list if {
	referenced_list_belong_to_users_groups
	not referenced_list_is_private
}

referenced_list_belong_to_user if {
	some i
	token.payload.sub == input.originalRecord._fromMetadata._ownerUsers[i]
}

# Only consider group ownership if the user is not a direct owner
referenced_list_belong_to_users_groups if {
	not referenced_list_belong_to_user
	some i
	token.payload.groups[i] in input.originalRecord._fromMetadata._ownerGroups
}

referenced_list_is_private if {
	input.originalRecord._fromMetadata._visibility == "private"
}

referenced_list_is_passive if {
	input.originalRecord._fromMetadata._validUntilDateTime != null
	time.parse_rfc3339_ns(input.originalRecord._fromMetadata._validUntilDateTime) <= time.now_ns()
}

# List must have validFrom set and in the past, and not be passive
referenced_list_valid_for_creation if {
	input.originalRecord._fromMetadata._validFromDateTime != null
	time.parse_rfc3339_ns(input.originalRecord._fromMetadata._validFromDateTime) < time.now_ns()
	not referenced_list_is_passive
}

# The caller must be able to see the target entity (toMetadata). This follows
# the same rules as findEntityById for members and visitors. Admins/editors
# are allowed via their own rules above.
caller_can_see_target_entity if {
	cited_entity_belong_to_user
	not cited_entity_is_passive
}

caller_can_see_target_entity if {
	cited_entity_belong_to_users_groups
	not cited_entity_is_passive
	not cited_entity_is_private
}

caller_can_see_target_entity if {
	cited_entity_is_public
	cited_entity_is_active
}

caller_can_see_target_entity if {
	cited_entity_has_viewer_user
	cited_entity_is_active
}

caller_can_see_target_entity if {
	cited_entity_has_viewer_group
	not cited_entity_is_private
	cited_entity_is_active
}

cited_entity_is_active if {
	input.originalRecord._toMetadata._validFromDateTime != null
	time.parse_rfc3339_ns(input.originalRecord._toMetadata._validFromDateTime) < time.now_ns()
	not cited_entity_is_passive
}

cited_entity_is_passive if {
	input.originalRecord._toMetadata._validUntilDateTime != null
	time.parse_rfc3339_ns(input.originalRecord._toMetadata._validUntilDateTime) <= time.now_ns()
}

cited_entity_is_public if {
	input.originalRecord._toMetadata._visibility == "public"
}

cited_entity_is_private if {
	input.originalRecord._toMetadata._visibility == "private"
}

cited_entity_belong_to_user if {
	some i
	token.payload.sub == input.originalRecord._toMetadata._ownerUsers[i]
}

# Only consider group ownership if the user is not a direct owner
cited_entity_belong_to_users_groups if {
	not cited_entity_belong_to_user
	some i
	token.payload.groups[i] in input.originalRecord._toMetadata._ownerGroups
}

cited_entity_has_viewer_user if {
	some i
	token.payload.sub == input.originalRecord._toMetadata._viewerUsers[i]
}

cited_entity_has_viewer_group if {
	some i
	token.payload.groups[i] in input.originalRecord._toMetadata._viewerGroups
}
