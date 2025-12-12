package policies.fields.policy

# data.policies.fields.data alias'ı olmadan tam yol kullanılıyor
import data.policies.fields.mapping
import data.policies.util.common.token

# import data.policies.util.common.array  <-- KALDIRILDI: Yerleşik array.concat kullanılacak

import future.keywords.if
import future.keywords.in

# -----------------------------------------------------------------------------
# MAIN ACCESS POINT
# -----------------------------------------------------------------------------

get_forbidden_fields(recordType, operation, kind) := forbidden_paths if {
	# 1. Identify roles possessed by the user that are defined in our system

	# Collect global roles
	global_roles := {role_name | some def in data.policies.fields.data.global_defaults; role_name := def.role}

	# Collect type-specific roles (safe access)
	record_def := object.get(data.policies.fields.data.definitions, recordType, {})
	type_defaults := object.get(record_def, "default", [])
	type_roles := {role_name | some def in type_defaults; role_name := def.role}

	# Union of potential roles
	all_potential_roles := global_roles | type_roles

	# Filter by what the user actually has
	matching_roles := {role_name |
		some role_name in all_potential_roles
		user_has_role(role_name)
	}

	# Ensure we have at least one matching role
	count(matching_roles) > 0

	# 2. Calculate forbidden "Key" sets for each matching role
	forbidden_sets := {keys |
		some role_name in matching_roles
		keys := calculate_keys_for_role(role_name, recordType, operation, kind)
	}

	# 3. Calculate Intersection
	merged_keys_set := intersection(forbidden_sets)

	# 4. Field-Level Permission Check
	effective_keys := [key |
		some key in merged_keys_set
		not user_has_field_permission(key, operation)
	]

	# 5. Path Resolution
	forbidden_paths := resolve_keys_to_paths(effective_keys)
}

# Fallback: Return empty list
get_forbidden_fields(_, _, _) := []

# -----------------------------------------------------------------------------
# GATEWAY ACCESS POINT
# -----------------------------------------------------------------------------

get_all_forbidden_fields(operation) := result if {
	record_types := object.keys(data.policies.fields.data.definitions)
	result := {rt: 
	build_record_type_forbidden_map(rt, operation) |
		rt := record_types[_]
	}
}

build_record_type_forbidden_map(recordType, operation) := {
	"default": get_forbidden_fields(recordType, operation, null),
	"kinds": kinds_map,
} if {
	record_def := data.policies.fields.data.definitions[recordType]

	# Safe access to kinds
	kinds_obj := object.get(record_def, "kinds", {})
	kinds_map := {kind: get_forbidden_fields(recordType, operation, kind) |
		some kind in object.keys(kinds_obj)
	}
}

# -----------------------------------------------------------------------------
# LOGIC HELPERS (Private)
# -----------------------------------------------------------------------------

calculate_keys_for_role(role_name, recordType, operation, kind) := key_set if {
	# Layer 1: Global
	global_keys := get_keys_from_role_operation(data.policies.fields.data.global_defaults, role_name, operation)

	# Layer 2: Type
	record_def := object.get(data.policies.fields.data.definitions, recordType, {})
	type_defaults := object.get(record_def, "default", [])
	type_keys := get_keys_from_role_operation(type_defaults, role_name, operation)

	# Layer 3: Kind
	kind_keys := get_kind_keys(record_def, kind, role_name, operation)

	# Merge using built-in array.concat
	all_list := array.concat(array.concat(global_keys, type_keys), kind_keys)
	key_set := {k | k := all_list[_]}
}

get_kind_keys(record_def, kind, role_name, operation) := keys if {
	kind != null

	# FIX: Safe access to 'kinds' dictionary
	kinds_dict := object.get(record_def, "kinds", {})
	kind_defs := object.get(kinds_dict, kind, null)
	keys := get_keys_from_role_operation(kind_defs, role_name, operation)
}

get_kind_keys(_, kind, _, _) := [] if {
	kind == null
}

get_keys_from_role_operation(definitions, target_role, operation) := keys if {
	definitions != null
	found := [k |
		def := definitions[_]
		def.role == target_role
		k := object.get(def.operations, operation, [])
	]
	count(found) > 0
	keys := found[0]
} else := []

resolve_keys_to_paths(keys) := paths if {
	paths := [
	mapping.keys[key] |
		key := keys[_]
		mapping.keys[key] != null
	]
}

# -----------------------------------------------------------------------------
# PERMISSION HELPERS
# -----------------------------------------------------------------------------

user_has_role(config_role_name) if {
	some token_role in token.payload.roles
	endswith(token_role, config_role_name)
}

user_has_field_permission(field_key, "find") if {
	app_shortcode := input.appShortcode
	some user_role in token.payload.roles
	pattern := sprintf(`%s\.(records|entities)\.fields\.%s\.(find|create|update|manage)`, [app_shortcode, field_key])
	regex.match(pattern, user_role)
}

user_has_field_permission(field_key, operation) if {
	operation != "find"
	app_shortcode := input.appShortcode
	some user_role in token.payload.roles
	pattern := sprintf(`%s\.(records|entities)\.fields\.%s\.(%s|manage)`, [app_shortcode, field_key, operation])
	regex.match(pattern, user_role)
}
