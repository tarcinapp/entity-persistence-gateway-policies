# Policy Skeleton — calc task on relations
#
# HOW TO USE THIS FILE
# --------------------
# 1. Copy this entire folder to a new folder named after your task:
#
#      cp -r extension/auth/routes/relations/calc/_skeleton \
#             extension/auth/routes/relations/calc/path-length
#
# 2. Update the `package` declaration below — replace `_skeleton`
#    with your task name (use hyphens for multi-word names, e.g. `path-length`):
#
#      package policies.auth.routes.relations.calc.path-length.policy
#
# 3. Replace every occurrence of `_skeleton` with your task name in the
#    `task_name` constant below.
#
# 4. Uncomment and adjust the `allow` rules that apply to your task.
#    The default rules below mirror `findRelationById`: admin/editor always
#    allowed; members can see relations they own; relations do not carry
#    group-ownership or visibility fields, so only ownership and public+active
#    checks apply.
#
# 5. Start OPA with both the framework and extension directories:
#
#      opa run --server ./policies ./extension
#
# No EPG route configuration change is ever needed. The exec/calc routes in
# application-routes.yml are shipped with a policyNameTemplate that resolves
# to /policies/auth/routes/relations/calc/{taskName}/policy at request time.
# As long as this folder name matches the task name registered in EPG's
# allow-list (app.tasks.relations.calc), the policy is automatically queried.
#
# SAFETY GUARANTEE
# ----------------
# This file contains no `allow` rules in uncommented form.
# Until you add them, this package returns `undefined` for `allow`,
# which the Gateway maps to 403 Forbidden — safe by default.
#
# NOTE: email_verified is NOT required by default for calc tasks
# (consistent with `findRelationById`). Add it explicitly if your task
# has elevated sensitivity.

package policies.auth.routes.relations.calc._skeleton.policy

import data.policies.util.common.originalRecord as original_record
import data.policies.util.relations.roles as role_utils

# The canonical task name — matches the folder name and the app-oas.yml declaration.
# Update this constant when you copy this skeleton to a real task folder.
task_name := "_skeleton"

# Default deny — required in every policy file.
default allow := false

# ---------------------------------------------------------------------------
# DEFAULT ACCESS RULES — mirrors findRelationById
#
# calc tasks are read-only; email_verified is NOT required by default.
# Relations do not carry group-ownership or viewer fields — only ownership
# and public+active visibility checks apply.
#
# Uncomment the rules below and adjust to your task's requirements.
# ---------------------------------------------------------------------------

# allow if {
#     role_utils.is_user_task_admin("calc", task_name, input.originalRecord)
# }

# allow if {
#     role_utils.is_user_task_editor("calc", task_name, input.originalRecord)
# }

# allow if {
#     role_utils.is_user_task_member("calc", task_name, input.originalRecord)
#     original_record.is_belong_to_user
#     not original_record.is_passive
# }

# allow if {
#     role_utils.is_user_task_visitor("calc", task_name, input.originalRecord)
#     original_record.is_public
#     original_record.is_active
# }
