package policies.gateway.forbidden_fields.policy

import data.policies.fields.policy as field_logic

# -----------------------------------------------------------------------------
# GATEWAY ENTRY POINT
# -----------------------------------------------------------------------------
# When Gateway queries this policy (data.policies.gateway.forbidden_fields.policy.result),
# it reads the operation from the input and queries the central logic engine.

default result := {}

result := forbidden_map if {
	# 1. Safely extract operation from input
	op := input.operation

	# 2. Validate operation (Optional security check)
	is_valid_operation(op)

	# 3. Call the Central Brain (Library)
	forbidden_map := field_logic.get_all_forbidden_fields(op)
}

# Optional: Return error object for invalid operations
# result := {"error": "Invalid operation"} if { not is_valid_operation(input.operation) }

# -----------------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------------

is_valid_operation(op) if {
	op in ["find", "create", "update"]
}
