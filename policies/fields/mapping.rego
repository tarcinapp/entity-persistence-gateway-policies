package policies.fields.mapping

# Mapping of Permission Keys to Dot-Notation Paths
# This centralized mapping allows permissions to reference logical keys
# rather than brittle path strings throughout the codebase.
# For now, all keys map to themselves (simple field names).
keys := {
	# Common / System Fields
	"_kind": "_kind",
	"_slug": "_slug",
	"_version": "_version",
	"_createdDateTime": "_createdDateTime",
	"_lastUpdatedDateTime": "_lastUpdatedDateTime",
	"_lastUpdatedBy": "_lastUpdatedBy",
	"_createdBy": "_createdBy",
	"_idempotencyKey": "_idempotencyKey",
	"_validFromDateTime": "_validFromDateTime",
	"_validUntilDateTime": "_validUntilDateTime",
	"_ownerUsers": "_ownerUsers",
	"_application": "_application",
	"_visibility": "_visibility",
	"_viewerUsers": "_viewerUsers",
	"_viewerGroups": "_viewerGroups",
	"_listId": "_listId",
	"_entityId": "_entityId",
	"_recordType": "_recordType",
}
