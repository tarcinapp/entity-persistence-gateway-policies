package policies.auth.routes.findRelationById.policy

import data.policies.util.common.token as token
import data.policies.util.common.verification as verification
import data.policies.util.relations.roles as role_utils

# By default, deny requests.
default allow = false

#-----------------------------------------------
# Decide allow if any of the following section is true
#-----------------------------------------------
# Admins and editors are allowed as long as the email is verified
allow if {
	role_utils.is_user_admin("find")
	verification.is_email_verified
}

allow if {
	role_utils.is_user_editor("find")
	verification.is_email_verified
}

# Members can see a relation only if they can see both source and target
allow if {
	role_utils.is_user_member("find")
	verification.is_email_verified
	can_user_see_source
	can_user_see_target
}

# Visitors can see a relation only when both source and target are public and active
allow if {
	role_utils.is_user_visitor("find")
	verification.is_email_verified
	from_is_public
	from_is_active
	to_is_public
	to_is_active
}

#-----------------------------------------------
# Helpers for evaluating visibility of the _fromMetadata (source)

from_is_active if {
	input.originalRecord._fromMetadata._validFromDateTime != null
	time.parse_rfc3339_ns(input.originalRecord._fromMetadata._validFromDateTime) < time.now_ns()
	not from_is_passive
}

from_is_passive if {
	input.originalRecord._fromMetadata._validUntilDateTime != null
	time.parse_rfc3339_ns(input.originalRecord._fromMetadata._validUntilDateTime) <= time.now_ns()
}

from_is_public if {
	input.originalRecord._fromMetadata._visibility == "public"
}

from_is_protected if {
	input.originalRecord._fromMetadata._visibility == "protected"
}

from_is_private if {
	input.originalRecord._fromMetadata._visibility == "private"
}

from_is_belong_to_user if {
	some i
	token.payload.sub = input.originalRecord._fromMetadata._ownerUsers[i]
}

# Only consider group ownership if the user is not a direct owner
from_is_belong_to_users_groups if {
	not from_is_belong_to_user
	some i
	token.payload.groups[i] in input.originalRecord._fromMetadata._ownerGroups
}

from_is_user_in_viewerUsers if {
	some i
	token.payload.sub = input.originalRecord._fromMetadata._viewerUsers[i]
}

from_is_user_in_viewerGroups if {
    some i
    token.payload.groups[i] in input.originalRecord._fromMetadata._viewerGroups
}

from_has_value(fieldName) if {
	input.originalRecord._fromMetadata[fieldName]
	input.originalRecord._fromMetadata[fieldName] != null
}

from_is_empty(fieldName) if {
	not from_has_value(fieldName)
}

#-----------------------------------------------
# Helpers for evaluating visibility of the _toMetadata (target)

to_is_active if {
	input.originalRecord._toMetadata._validFromDateTime != null
	time.parse_rfc3339_ns(input.originalRecord._toMetadata._validFromDateTime) < time.now_ns()
	not to_is_passive
}

to_is_passive if {
	input.originalRecord._toMetadata._validUntilDateTime != null
	time.parse_rfc3339_ns(input.originalRecord._toMetadata._validUntilDateTime) <= time.now_ns()
}

to_is_public if {
	input.originalRecord._toMetadata._visibility == "public"
}

to_is_protected if {
	input.originalRecord._toMetadata._visibility == "protected"
}

to_is_private if {
	input.originalRecord._toMetadata._visibility == "private"
}

to_is_belong_to_user if {
	some i
	token.payload.sub = input.originalRecord._toMetadata._ownerUsers[i]
}

# Only consider group ownership if the user is not a direct owner
to_is_belong_to_users_groups if {
	not to_is_belong_to_user
	some i
	token.payload.groups[i] in input.originalRecord._toMetadata._ownerGroups
}

to_is_user_in_viewerUsers if {
	some i
	token.payload.sub = input.originalRecord._toMetadata._viewerUsers[i]
}

to_is_user_in_viewerGroups if {
    some i
    token.payload.groups[i] in input.originalRecord._toMetadata._viewerGroups
}

to_has_value(fieldName) if {
	input.originalRecord._toMetadata[fieldName]
	input.originalRecord._toMetadata[fieldName] != null
}

to_is_empty(fieldName) if {
	not to_has_value(fieldName)
}

#-----------------------------------------------
# Compose visibility predicates for source and target

can_user_see_source if {
	from_is_belong_to_user
	not from_is_passive                # record is either pending or active
}

can_user_see_source if {
	from_is_belong_to_users_groups
	not from_is_passive                # record is either pending or active
	not from_is_private                # record is either public or protected
}

can_user_see_source if {
	from_is_public
	from_is_active
}

can_user_see_source if {
	from_is_user_in_viewerUsers
	from_is_active
}

can_user_see_source if {
	from_is_user_in_viewerGroups
	not from_is_private                # record is either public or protected
	from_is_active
}

# Target visibility follows the same set of rules as entities/lists
can_user_see_target if {
	to_is_belong_to_user
	not to_is_passive                # record is either pending or active
}

can_user_see_target if {
	to_is_belong_to_users_groups
	not to_is_passive                # record is either pending or active
	not to_is_private                # record is either public or protected
}

can_user_see_target if {
	to_is_public
	to_is_active
}

can_user_see_target if {
	to_is_user_in_viewerUsers
	to_is_active
}

can_user_see_target if {
	to_is_user_in_viewerGroups
	not to_is_private                # record is either public or protected
	to_is_active
}
