# exec Task Policies

This folder contains authorization policies for `exec` task endpoints on entity records.

`exec` tasks are state-mutating, operational endpoints of the form:

```
POST /api/v1/entities/{id}/exec/{taskname}
```

Each task has its own sub-folder, its own `policy.rego`, and its own tests — following the same structure as every other operation folder in this repository (e.g. `createEntity/`, `updateEntityById/`).

## Framework-shipped tasks

Tasks shipped with the Tarcinapp framework are listed here as sub-folders when they exist.

## Product-defined tasks

Task names are product-specific (`merge`, `archive`, `publish`, …). Product teams implement policies for their own tasks using the **OPA Policy Extension Pattern** — see [`policies/extension/README.md`](../../../extension/README.md).

## Policy structure

Each task policy follows the same conventions as other write-operation policies in this repository:

- `default allow := false` is mandatory
- `verification.is_email_verified` is required for all roles
- `input.originalRecord` carries the target entity's metadata for ownership/visibility checks
- `input.requestPayload` carries the task parameters

See [`../createEntity/policy.rego`](../createEntity/policy.rego) and [`../updateEntityById/policy.rego`](../updateEntityById/policy.rego) as reference implementations.
