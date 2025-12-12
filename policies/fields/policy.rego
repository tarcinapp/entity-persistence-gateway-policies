package policies.fields.policy

import data.policies.fields.data as fields_data
import data.policies.fields.mapping
import data.policies.util.common.array
import data.policies.util.common.roleDispatcher as dispatcher
import data.policies.util.common.token
import future.keywords.if
import future.keywords.in

# -----------------------------------------------------------------------------
# 1. MAIN ACCESS POINT (Internal Auth Policies)
# -----------------------------------------------------------------------------

# Default to empty list if no role is found or other conditions fail.
default get_forbidden_fields(_, _, _) := []

# get_forbidden_fields(recordType, operation, source_object)
#
# Returns the list of forbidden field paths (dot-notation) for a specific context.
#
# Inputs:
#   - recordType: "entities", "lists", etc.
#   - operation: "find", "create", "update"
#   - source_object: The payload or original record (used to determine kind and effective role)
#
# Logic Flow:
#   1. Determine Effective Role via Dispatcher (Admin > Editor > Member > Visitor)
#   2. Merge Forbidden Lists (Global + RecordType + Kind) based on that role.
#   3. Prune fields where the user has specific "Field-Level Permission" (The "Skeleton Key").
#   4. Map internal keys to actual JSON paths.
get_forbidden_fields(recordType, operation, source_object) := forbidden_paths if {
	# Step 1: Determine Effective Role
	# We ask the dispatcher: "What is this user's role for this specific object?"
	role := dispatcher.get_effective_role(recordType, operation, source_object)
	role != null

	# Step 2: Merge Forbidden Lists (Layered Inheritance)

	# Layer A: Global Defaults
	global_keys := get_keys_from_def(fields_data.global_defaults, role, operation)

	# Layer B: Record Type Defaults
	type_def := object.get(fields_data.definitions, recordType, {})
	type_defaults := object.get(type_def, "default", [])
	type_keys := get_keys_from_def(type_defaults, role, operation)

	# Layer C: Kind Specifics
	# Extract kind safely from source object
	kind := safe_kind(source_object)
	kind_keys := get_kind_keys(type_def, kind, role, operation)

	# Union of all layers
	all_keys := array.concat(array.concat(global_keys, type_keys), kind_keys)

	# Step 3: Field-Level Permission Check (Pruning)
	# If the user has a specific permission for a field (e.g., ...fields._slug.update),
	# remove it from the forbidden list.
	effective_keys := [key |
		some key in all_keys
		not user_has_field_permission(recordType, kind, key, operation)
	]

	# Step 4: Resolve to Paths
	forbidden_paths := resolve_keys_to_paths(effective_keys)
}

# -----------------------------------------------------------------------------
# 2. GATEWAY ACCESS POINT (Global Map)
# -----------------------------------------------------------------------------

# get_all_forbidden_fields(operation)
#
# Returns a complete map of forbidden fields for ALL record types and kinds.
# Used by the API Gateway to filter responses globally.
#
# Logic:
#   Iterates through all definitions and simulates the check with a null source object
#   (defaulting to the base kind logic) and specific kind objects.
get_all_forbidden_fields(operation) := result if {
	record_types := object.keys(fields_data.definitions)
	result := {rt: build_gateway_map(rt, operation) |
		rt := record_types[_]
	}
}

build_gateway_map(recordType, operation) := {
	"default": get_forbidden_fields(recordType, operation, null),
	"kinds": kinds_map,
} if {
	type_def := fields_data.definitions[recordType]

	# Iterate over defined kinds to pre-calculate their specific forbidden lists
	kinds_map := {kind: get_forbidden_fields(recordType, operation, {"_kind": kind}) |
		some kind in object.keys(object.get(type_def, "kinds", {}))
	}
}

# -----------------------------------------------------------------------------
# 3. DATA HELPERS
# -----------------------------------------------------------------------------

# Helper: Extract keys for a specific role/op from a definition list
get_keys_from_def(definition_list, role, operation) := keys if {
	definition_list != null

	# Find the entry matching the role
	found := [k |
		def := definition_list[_]
		def.role == role
		k := object.get(def.operations, operation, [])
	]

	# Take the first match (flattening)
	count(found) > 0
	keys := found[0]
} else := []

# Helper: Get keys for a specific kind
get_kind_keys(type_def, kind, role, operation) := keys if {
	kind != null
	kinds_def := object.get(type_def, "kinds", {})
	specific_kind_def := object.get(kinds_def, kind, null)
	keys := get_keys_from_def(specific_kind_def, role, operation)
} else := []

# Helper: Extract _kind safely
default safe_kind(_) := null

safe_kind(obj) := object.get(obj, "_kind", null) if is_object(obj)

# Helper: Map keys to dot-notation paths
resolve_keys_to_paths(keys) := paths if {
	paths := [mapping.keys[k] | k := keys[_]; mapping.keys[k]]
}

# -----------------------------------------------------------------------------
# 4. FIELD-LEVEL PERMISSION CHECK
# -----------------------------------------------------------------------------

# user_has_field_permission(recordType, kind, fieldKey, operation)
# Checks if the user has a specific role granting access to a forbidden field.
#
# Regex Format Supported:
#   tarcinapp.fields.<scope>.<kind?>.<fieldKey>.<permission>
#
#   <scope>:      (records|entities) for entities, (records|lists) for lists, etc.
#   <kind?>:      Optional. If present, specific to that kind.
#   <permission>: Depends on operation (see below).
user_has_field_permission(recordType, kind, fieldKey, operation) if {
	app := input.appShortcode
	scope_pattern := get_resource_scope_pattern(recordType)
	kind_pattern := get_kind_regex_part(kind)
	op_pattern := get_operation_pattern(operation)

	# NEW Hierarchy: tarcinapp.fields.<scope>.<kind>.<field>.<op>
	# Regex: ^tarcinapp\.fields\.(records|entities)(\.book)?\._slug\.(update|manage)$
	pattern := sprintf(`^%s\.fields\.%s%s\.%s\.%s$`, [app, scope_pattern, kind_pattern, fieldKey, op_pattern])

	some user_role in token.payload.roles
	regex.match(pattern, user_role)
}

# Map recordType to Regex Scope using a Lookup Object (Prevents eval_conflict_error)
get_resource_scope_pattern(rt) := pattern if {
	scope_map := {
		"entities": "(records|entities)",
		"lists": "(records|lists)",
		"relations": "relations",
		"entityReactions": "(reactions|entityReactions)",
		"listReactions": "(reactions|listReactions)",
	}

	# Default to match anything/wildcard if not found, or handle as needed
	pattern := object.get(scope_map, rt, ".*")
}

# Build Kind Regex Part
default get_kind_regex_part(_) := ""

get_kind_regex_part(kind) := sprintf(`(\.%s)?`, [kind]) if {
	kind != null
	kind != ""
}

# Map Operation to Permission Regex
# Find: Can be viewed by find, create, update, or manage roles
get_operation_pattern("find") := "(find|create|update|manage)"

# Create/Update: Can be modified by specific op or manage
get_operation_pattern(op) := sprintf(`(%s|manage)`, [op]) if {
	op != "find"
}
