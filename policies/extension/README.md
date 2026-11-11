# Extension Policies — OPA Policy Extension Pattern

This directory is the designated root for all product-defined and product-overridden policies. The framework directory (`policies/auth/`, `policies/fields/`, `policies/util/`) is never modified by product teams.

---

## What is the OPA Policy Extension Pattern?

The **OPA Policy Extension Pattern** is the mechanism by which product teams add or override **any** route authorization policy without modifying any file inside the framework directory.

It exploits two OPA behaviours:

1. **Default deny by undefined.** If no `.rego` file declares a package that the Gateway queries, OPA returns `undefined`. The Gateway maps `undefined` to `403 Forbidden`. Any unimplemented policy is automatically safe — no action needed.

2. **Package merging across load paths.** OPA merges all rules from every file that shares the same `package` declaration, regardless of which directory each file came from. A product file in `extension/` and a framework file in `policies/auth/` can both contribute rules to the same package.

---

## Directory structure

```
extension/
├── README.md                          ← this file
└── auth/
    └── routes/
        └── {resourceType}/
            ├── exec/
            │   └── {taskname}/
            │       ├── policy.rego        ← package policies.auth.routes.{resourceType}.exec.{taskname}.policy
            │       ├── policy_test.rego
            │       └── README.md
            └── calc/
                └── {taskname}/
                    ├── policy.rego        ← package policies.auth.routes.{resourceType}.calc.{taskname}.policy
                    ├── policy_test.rego
                    └── README.md
```

**Example** — a product that implements `exec/merge` on entities and `calc/average-amount` on entities:

```
extension/
└── auth/
    └── routes/
        └── entities/
            ├── exec/
            │   └── merge/
            │       ├── policy.rego
            │       ├── policy_test.rego
            │       └── README.md
            └── calc/
                └── average-amount/
                    ├── policy.rego
                    ├── policy_test.rego
                    └── README.md
```

---

## How to create a new task policy

**Step 1 — Copy the skeleton** for the appropriate family:

```bash
# For an exec task on entities:
cp -r extension/auth/routes/entities/exec/_skeleton \
      extension/auth/routes/entities/exec/merge

# For a calc task on entities:
cp -r extension/auth/routes/entities/calc/_skeleton \
      extension/auth/routes/entities/calc/average-amount
```

**Step 2 — Update the `package` declaration** in `policy.rego`:

```rego
# exec task:
package policies.auth.routes.entities.exec.merge.policy

# calc task:
package policies.auth.routes.entities.calc.average-amount.policy
```

**Step 3 — Implement `allow` rules.** All framework utilities are available as imports — they are resolved from the same OPA data namespace:

```rego
import data.policies.util.entities.roles as role_utils
import data.policies.util.common.originalRecord as original_record
import data.policies.util.common.verification as verification
```

**Step 4 — Start OPA** with both the framework directory and this extension directory in the load path:

```bash
# Development
opa run --watch --server ./policies ./extension

# Docker / production
CMD ["run", "--server", "--addr", "0.0.0.0:8181", "/policies", "/extension"]
```

> No EPG route configuration change is ever needed. The exec/calc routes in `application-routes.yml` are shipped with a `policyNameTemplate` that resolves to `/policies/auth/routes/{resourceType}/{family}/{taskName}/policy` at request time. As long as the folder name you created in step 1 matches the task name registered in the gateway's allow-list, the policy is automatically queried — OPA's merged namespace makes framework and extension files indistinguishable.

**Step 5 — Write tests** in `policy_test.rego`. Use `data.policies.util.common.test.produce_token()` to generate test JWTs. See any `policy_test.rego` in `policies/auth/routes/entities/` for examples.

---

## Safety properties

| Scenario | Outcome |
|:---|:---|
| Task registered in EPG, no policy file in `extension/` | OPA returns `undefined` → Gateway returns `403` |
| Policy file exists with only `default allow := false` | All requests denied — safe to deploy as a placeholder |
| Product file and framework file share the same package | Rules merged; either file's `allow` rules can grant access |
| `extension/` is not mounted at OPA startup | All task requests denied (framework policies alone contain no task `allow` rules) |

---

## Skeleton files

Each resource type's `exec/` and `calc/` folders contain a `_skeleton/` sub-folder with a copy-and-fill template. The `_skeleton` name is never registered as a task in any gateway route configuration — it is documentation only.

- [`auth/routes/entities/exec/_skeleton/policy.rego`](./auth/routes/entities/exec/_skeleton/policy.rego)
- [`auth/routes/entities/calc/_skeleton/policy.rego`](./auth/routes/entities/calc/_skeleton/policy.rego)
