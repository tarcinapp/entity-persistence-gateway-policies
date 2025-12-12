package policies.util.lists.roles

import data.policies.util.common.token as token

# Helper to construct the resource part of the regex
resource_scope := "(records|lists)"

# Helper to safely extract _kind from source object
default safe_kind(_) := null

safe_kind(obj) := object.get(obj, "_kind", null) if {
	is_object(obj)
}

# ------------------------------------------------------------------------------
# ADMIN CHECK
# ------------------------------------------------------------------------------
is_user_admin(operation, source_object) if {
	role := token.payload.roles[_]
	kind := safe_kind(source_object)
	kind_pattern := kind_regex_part(kind)
	pattern := sprintf(`^%s(\.%s%s(\.%s)?)?\.admin$`, [input.appShortcode, resource_scope, kind_pattern, operation])
	regex.match(pattern, role)
}

# ------------------------------------------------------------------------------
# EDITOR CHECK
# ------------------------------------------------------------------------------
is_user_editor(operation, source_object) if {
	not is_user_admin(operation, source_object)
	role := token.payload.roles[_]
	kind := safe_kind(source_object)
	kind_pattern := kind_regex_part(kind)
	pattern := sprintf(`^%s(\.%s%s(\.%s)?)?\.editor$`, [input.appShortcode, resource_scope, kind_pattern, operation])
	regex.match(pattern, role)
}

# ------------------------------------------------------------------------------
# MEMBER CHECK
# ------------------------------------------------------------------------------
is_user_member(operation, source_object) if {
	not is_user_admin(operation, source_object)
	not is_user_editor(operation, source_object)
	role := token.payload.roles[_]
	kind := safe_kind(source_object)
	kind_pattern := kind_regex_part(kind)
	pattern := sprintf(`^%s(\.%s%s(\.%s)?)?\.member$`, [input.appShortcode, resource_scope, kind_pattern, operation])
	regex.match(pattern, role)
}

# ------------------------------------------------------------------------------
# VISITOR CHECK
# ------------------------------------------------------------------------------
is_user_visitor(operation, source_object) if {
	not is_user_admin(operation, source_object)
	not is_user_editor(operation, source_object)
	not is_user_member(operation, source_object)
	role := token.payload.roles[_]
	kind := safe_kind(source_object)
	kind_pattern := kind_regex_part(kind)
	pattern := sprintf(`^%s(\.%s%s(\.%s)?)?\.visitor$`, [input.appShortcode, resource_scope, kind_pattern, operation])
	regex.match(pattern, role)
}

# ------------------------------------------------------------------------------
# HELPER
# ------------------------------------------------------------------------------
default kind_regex_part(_) := ""

kind_regex_part(kind) := sprintf(`(\.%s)?`, [kind]) if {
	kind != null
	kind != ""
}
