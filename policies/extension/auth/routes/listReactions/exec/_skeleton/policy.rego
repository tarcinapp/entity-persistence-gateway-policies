# Policy Skeleton — exec task on listReactions
#
# HOW TO USE THIS FILE
# --------------------
# 1. Copy this entire folder to a new folder named after your task:
#
#      cp -r extension/auth/routes/listReactions/exec/_skeleton \
#             extension/auth/routes/listReactions/exec/flag
#
# 2. Update the `package` declaration below — replace `_skeleton`
#    with your task name (use hyphens for multi-word names, e.g. `send-notification`):
#
#      package policies.auth.routes.listReactions.exec.flag.policy
#
# 3. Replace every occurrence of `_skeleton` with your task name in the
#    `task_name` constant below.
#
# 4. Uncomment and adjust the `allow` rules that apply to your task.
#    The default rules below mirror `updateListReactionById`: admin/editor always
#    allowed; members must own the record and the record must not be expired.
#
# 5. Start OPA with both the framework and extension directories:
#
#      opa run --server ./policies ./extension
#
# No EPG route configuration change is ever needed. The exec/calc routes in
# application-routes.yml are shipped with a policyNameTemplate that resolves
# to /policies/auth/routes/listReactions/exec/{taskName}/policy at request time.
# As long as this folder name matches the task name registered in EPG's
# allow-list (app.tasks.listReactions.exec), the policy is automatically queried.
#
# SAFETY GUARANTEE
# ----------------
# This file contains no `allow` rules in uncommented form.
# Until you add them, this package returns `undefined` for `allow`,
# which the Gateway maps to 403 Forbidden — safe by default.

package policies.auth.routes.listReactions.exec._skeleton.policy

import data.policies.util.common.originalRecord as original_record
import data.policies.util.common.verification as verification
import data.policies.util.listReactions.roles as role_utils

# The canonical task name — matches the folder name and the app-oas.yml declaration.
# Update this constant when you copy this skeleton to a real task folder.
task_name := "_skeleton"

# Default deny — required in every policy file.
default allow := false

# ---------------------------------------------------------------------------
# DEFAULT ACCESS RULES — mirrors updateListReactionById
#
# exec tasks are state-mutating; email_verified is required for all roles.
#
# Uncomment the rules below and adjust to your task's requirements.
# ---------------------------------------------------------------------------

# allow if {
#     role_utils.is_user_task_admin("exec", task_name, input.originalRecord)
#     verification.is_email_verified
# }

# allow if {
#     role_utils.is_user_task_editor("exec", task_name, input.originalRecord)
#     verification.is_email_verified
# }

# allow if {
#     role_utils.is_user_task_member("exec", task_name, input.originalRecord)
#     verification.is_email_verified
#     original_record.is_belong_to_user   # caller must own the reaction
#     not original_record.is_passive      # deny on expired records
# }
