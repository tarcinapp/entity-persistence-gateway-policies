package policies.util.common.fields

import future.keywords.if
import future.keywords.in

# payload_contains(payload, field_path_str)
# Check if the given payload contains the field specified by field_path_str (dot notation).
# Handles array traversal implicitly by normalizing walk paths to remove integer indices.
payload_contains(payload, field_path_str) if {
	target_path := split(field_path_str, ".")
	walk(payload, [path, _])
	normalized_path := [p | p := path[_]; not is_number(p)]
	normalized_path == target_path
}

# is_field_changed(payload, original_record, field_path_str)
# Determine if a specific field has a different value in payload compared to original_record.
# Returns true if:
# - The old value is missing (new field being added), OR
# - The new value differs from the old value

# Case 1: Field is new (missing in original record)
is_field_changed(payload, original_record, field_path_str) if {
	target_path := split(field_path_str, ".")
	walk(payload, [exact_path, _])
	normalized_path := [p | p := exact_path[_]; not is_number(p)]
	normalized_path == target_path
	object.get(original_record, exact_path, "___MISSING___") == "___MISSING___"
}

# Case 2: Field exists but has changed value
is_field_changed(payload, original_record, field_path_str) if {
	target_path := split(field_path_str, ".")
	walk(payload, [exact_path, new_value])
	normalized_path := [p | p := exact_path[_]; not is_number(p)]
	normalized_path == target_path
	old_value := object.get(original_record, exact_path, "___MISSING___")
	old_value != "___MISSING___"
	new_value != old_value
}

# Keep get_value_by_path as is (using set comprehension)
get_value_by_path(obj, field_path_str) := values if {
	target_path := split(field_path_str, ".")
	values := {v |
		walk(obj, [exact_path, v])
		normalized_path := [p | p := exact_path[_]; not is_number(p)]
		normalized_path == target_path
	}
}
