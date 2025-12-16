package policies.fields.data

# Centralized forbidden fields definitions using STRICT Inheritance Model
# Layer 1: Global Defaults - Common rules for ALL record types (Admin, Editor, Visitor)
# Layer 2: Type-Specific Deltas - ONLY fields that DIFFER from global defaults
# Layer 3: Kind-Specific Overrides - Kind-level exceptions (future use)

# Global Defaults (Base Layer)
# These rules apply to ALL record types. Overrides happen at type level ONLY for differences.
global_defaults := [
	{
		"role": "admin",
		"operations": {
			"find": [],
			"create": [],
			"update": [],
		},
	},
	{
		"role": "editor",
		"operations": {
			"find": ["_recordType"],
			"create": ["_recordType", "_createdDateTime", "_lastUpdatedDateTime", "_lastUpdatedBy", "_createdBy", "_idempotencyKey"],
			"update": ["_recordType", "_kind", "_createdDateTime", "_lastUpdatedDateTime", "_lastUpdatedBy", "_createdBy", "_idempotencyKey"],
		},
	},
	{
		"role": "member",
		"operations": {
			"find": ["_recordType", "_version", "_idempotencyKey", "_application"],
			"create": ["_recordType", "_ownerUsers", "_createdDateTime", "_lastUpdatedDateTime", "_lastUpdatedBy", "_createdBy", "_validFromDateTime", "_validUntilDateTime", "_application", "_version", "_idempotencyKey"],
			"update": ["_recordType", "_kind", "_createdDateTime", "_lastUpdatedDateTime", "_lastUpdatedBy", "_createdBy", "_validFromDateTime", "_validUntilDateTime", "_application", "_version", "_idempotencyKey"], # valid until is added as it requires additional role to inactivate the record for members
		},
	},
	{
		"role": "visitor",
		"operations": {"find": ["_recordType", "_validFromDateTime", "_validUntilDateTime", "_visibility", "_version", "_lastUpdatedBy", "_lastUpdatedDateTime", "_idempotencyKey", "_viewerUsers", "_viewerGroups", "_application", "_idempotencyKey"]},
	},
]

# Record Type Deltas (Only define what DIFFERS from global_defaults)
# Most operations at global -> record level only contains ADDITIONS/DIFFERENCES
definitions := {
	"entities": {
		"default": [{
			"role": "member",
			"operations": {
				"create": ["_slug"],
				"update": ["_slug"],
			},
		}],
		"kinds": {},
	},
	"lists": {
		"default": [{
			"role": "member",
			"operations": {
				"create": ["_slug"],
				"update": ["_slug"],
			},
		}],
		"kinds": {},
	},
	"relations": {
		"default": [
			{
				"role": "admin",
				"operations": {"update": ["_fromMetadata", "_toMetadata"]},
			},
			{
				"role": "editor",
				"operations": {"update": ["_fromMetadata", "_toMetadata"]},
			},
			{
				"role": "member",
				"operations": {
					"update": ["_entityId", "_listId", "_fromMetadata", "_toMetadata"],
					"create": [],
				},
			},
		],
		"kinds": {},
	},
	"entityReactions": {
		"default": [{
			"role": "member",
			"operations": {"update": ["_entityId"]},
		}],
		"kinds": {},
	},
	"listReactions": {
		"default": [{
			"role": "member",
			"operations": {"update": ["_listId"]},
		}],
		"kinds": {},
	},
}
