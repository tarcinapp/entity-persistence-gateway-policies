# Policy Skeleton — calc task on entityReactions
#
# HOW TO USE THIS FILE
# --------------------
# 1. Copy this entire folder to a new folder named after your task:
#
#      cp -r extension/auth/routes/entityReactions/calc/_skeleton \
#             extension/auth/routes/entityReactions/calc/sentiment-score
#
# 2. Update the `package` declaration below — replace `_skeleton`
#    with your task name (use hyphens for multi-word names, e.g. `sentiment-score`):
#
#      package policies.auth.routes.entityReactions.calc.sentiment-score.policy
#
# 3. Replace every occurrence of `_skeleton` with your task name in the
#    `task_name` constant below.
#
# 4. Uncomment and adjust the `allow` rules that apply to your task.
#    The default rules below mirror `findEntityReactionById`: admin/editor always
#    allowed; members can see their own or group-owned reactions; visitors
#    can only access public + active reactions.
#
# 5. Start OPA with both the framework and extension directories:
#
#      opa run --server ./policies ./extension
#
# No EPG route configuration change is ever needed. The exec/calc routes in
# application-routes.yml are shipped with a policyNameTemplate that resolves
# to /policies/auth/routes/entityReactions/calc/{taskName}/policy at request time.
# As long as this folder name matches the task name registered in EPG's
# allow-list (app.tasks.entityReactions.calc), the policy is automatically queried.
#
# SAFETY GUARANTEE
# ----------------
# This file contains no `allow` rules in uncommented form.
# Until you add them, this package returns `undefined` for `allow`,
# which the Gateway maps to 403 Forbidden — safe by default.
#
# NOTE: email_verified is NOT required by default for calc tasks
# (consistent with `findEntityReactionById`). Add it explicitly if your task
# has elevated sensitivity.

package policies.auth.routes.entityReactions.calc._skeleton.policy

import data.policies.util.common.originalRecord as original_record
import data.policies.util.entityReactions.roles as role_utils

# The canonical task name — matches the folder name and the app-oas.yml declaration.
# Update this constant when you copy this skeleton to a real task folder.
task_name := "_skeleton"

# Default deny — required in every policy file.
default allow := false

# ---------------------------------------------------------------------------
# DEFAULT ACCESS RULES — mirrors findEntityReactionById
#
# calc tasks are read-only; email_verified is NOT required by default.
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
#     can_user_see_this_record
# }

# allow if {
#     role_utils.is_user_task_visitor("calc", task_name, input.originalRecord)
#     original_record.is_public
#     original_record.is_active
# }

# ---------------------------------------------------------------------------
# VISIBILITY HELPERS — identical to findEntityReactionById visibility checks
# ---------------------------------------------------------------------------

# can_user_see_this_record if {
#     original_record.is_belong_to_user
#     not original_record.is_passive
# }

# can_user_see_this_record if {
#     original_record.is_belong_to_users_groups
#     not original_record.is_passive
#     not original_record.is_private
# }

# can_user_see_this_record if {
#     original_record.is_public
#     original_record.is_active
# }

# can_user_see_this_record if {
#     original_record.is_user_in_viewerUsers
#     original_record.is_active
# }

# can_user_see_this_record if {
#     original_record.is_user_in_viewerGroups
#     not original_record.is_private
#     original_record.is_active
# }
