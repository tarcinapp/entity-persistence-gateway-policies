# Overview
The **Entity Persistence Policies** component is a layer within the **Tarcinapp Suite**, designed to enhance the security and fine-grained control of REST-based flows exposed using entity-persistence-gateway. Built upon the Open Policy Agent (OPA) framework and containerized for seamless integration, this component empowers gateway application with the ability to enforce complex policies that determine user actions and field-level access.  
This application seamlessly integrates with the Tarcinapp Suite's managed fields, ensuring efficient policy enforcement for fields like `ownerUsers`, `ownerGroups`, `visibility`, `validFromDateTime`, `validUntilDateTime`, etc..  

**Key Features**  
**User Action Policies**: Entity Persistence Policies enables you to define granular policies that govern user actions within your application. These policies help answer questions like "Can a user perform a specific action?" or "Is this user authorized to execute this operation?".  
  
**Field-Level Access Policies**: With Entity Persistence Policies, you can finely control access to fields in your data model. You have the flexibility to set policies that dictate whether a user can view, create, or update a particular field, providing a data security layer for your application.  
  
By leveraging the power of OPA-based policies, admins and developers ensure that the Tarcinapp application is shielded from unauthorized access, while simultaneously simplifying the enforcement of complex authorization rules. This component helps you reduce development time, enhance security, and streamline the creation of efficient and productive REST-based applications.

## What is Tarcinapp Suite?

The Tarcinapp suite is a comprehensive and flexible application framework, harmoniously blending a suite of interconnected components designed to deliver a seamless and secure microservices architecture. It also provides the flexibility for users to leverage it as an upstream project for their own REST API-based backend implementations, allowing for easy adaptation to their specific requirements and use cases.

<p align="center">
  <img src="./doc/img/tarcinapp.png" alt="Tarcinapp Suite Overview">
</p>

At its core is the **Entity Persistence Service**, an easily adaptable REST-based backend application built on the [Loopback 4](https://loopback.io) framework. This service utilizes on a schemaless MongoDB database to provide a scalable and highly adaptable data persistence layer. Offering a generic data model with predefined fields such as `id`, `name`,  `kind`, `lastUpdateDateTime`, `creationDateTime`, `ownerUsers` and [more](#programming-conventions), it effortlessly adapts to diverse use cases.  

The integration with the **Entity Persistence Gateway** empowers users to implement enhanced validation, authentication, authorization, and rate-limiting functionalities, ensuring a secure and efficient environment. Leveraging the power of **Redis**, the application seamlessly manages distributed locks, enabling robust data synchronization and rate limiting. Furthermore, the ecosystem includes the **Open Policy Agent (OPA)** to enforce policies, safeguarding your application against unauthorized access and ensuring compliance with your security and operational requirements. These policies, combined with the entire suite of components, form a cohesive and powerful ecosystem, paving the way for efficient and secure microservice development.  
Here is an example request and response to the one of the most basic endpoint: `/generic-entities`:
<p align="left">
  <img src="./doc/img/request-response.png" alt="Sample request and response">
</p>  

**Note:** The client's authorization to create an entity, the fields that user can specify, and the fields returned in the response body may vary based on the user's role. The values of managed fields such as `visibility`, `idempotencyKey`, `validFromDateTime`, and `validUntilDateTime` can also be adjusted according to the user's role and the system's configuration.  
  
**Note**: Endpoints can be configured with arbitrary values within the gateway component. For example, `/books` can be used for records with `kind: book`, and the field `kind` can be completely omitted from the API interaction.

# Entity Persistence Policies Application in Detail
The Entity Persistence Policies application operates as a REST API, serving requests on port 8181. The application processes policies based on their location within the project structure. Understanding the structure is essential for executing policies effectively.

### Policy Organization

- **Authentication Policies**: These policies, responsible for answering questions like "Can the user perform this operation?" are placed within the `/policies/auth/routes` directory. Each folder contains required files to form an OPA policy. Actual policy file is named as `policy.rego` under each route.

- **Field Policies**: These policies handle questions such as "Can the user view, create, or modify a specific field?" and are located in the `/policies/fields` directory. You can find folders named with record types (e.g. generic-entities, lists, etc).

### Executing Policies
To execute a policy, follow these steps:
1. Determine the policy type (authentication/routes or field-related).
2. Compose a request based on the policy type and policy name.  
For example: 
   - To execute a policy to check if a user is authorized to call `findEntities`, make an HTTP POST request to the following endpoint: `/v1/data/policies/auth/routes/findEntities/policy`. Request body should contain the required [policy execution input](#policy-execution-input) built properly. 
   - To get what fields are forbidden for a specific user to view, create or modify, perform an HTTP POST request to: `/v1/data/policies/fields/generic-entities/policy`. Request body should contain the required [policy execution input](#policy-execution-input) built properly. 

Understanding the project structure and endpoint designations is crucial for precise policy execution. Utilize this guide to seamlessly interact with Entity Persistence Policies and enforce authorization and access control based on your use case.

### Policy Execution Input
This section outlines the required input parameters for executing policies within the Entity Persistence Service. In this example, we'll focus on a PATCH request; however, please note that GET, POST, and PUT requests are also acceptable in the application.

- **policyName**: The policy name to be executed (e.g., "/policies/auth/routes/updateEntityById/policy").

- **appShortcode**: The shortcode of the application (e.g., "tarcinapp"). This helps administrator to give users different roles on different applications.

- **httpMethod**: The HTTP method used for the request (e.g., "GET", "POST", "PUT",  "PATCH").

- **requestPath**: The request path that corresponds to the reques (e.g., "/generic-entities", "/generic-entities/e613c7d0-3ea4-4815-80b6-eeb7e6f37b3e").

- **queryParams**: Any query parameters included in the request if any (e.g., "page": "2").

- **encodedJwt**: The encoded JSON Web Token (JWT) associated with the user's request.

- **requestPayload**: The payload specific to the request. For example, when creating a new record, this field contains the whole payload as a JSON object.

- **originalRecord**: If applicable, the original record as a whole that corresponds to the request.

Sample policy input:
```json
{
    "policyName": "/policies/auth/routes/updateEntityById/policy",
    "appShortcode": "tarcinapp",
    "httpMethod": "PATCH",
    "requestPath": "/generic-entities/e613c7d0-3ea4-4815-80b6-eeb7e6f37b3e",
    "queryParams": {}, // not applicable for PATCH. Applicable for GET
    "encodedJwt": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJrVG1OeGhSNExXZGhKeG5rV082d25NNHcybkFrcU5uWGFMOFZuR2JCLVFvIn0.eyJleHAiOjE2OTc4NzQxMzcsImlhdCI6MTY5NzgzODEzNywianRpIjoiZjhmODExZWQtZmVlYy00NDRkLTlkNTQtMmVhOWQ2ZjIzNGRkIiwiaXNzIjoiaHR0cHM6Ly90YXJjaW5hcHAta2V5Y2xvYWsuaDN0NGVnLmVhc3lwYW5lbC5ob3N0L3JlYWxtcy90YXJjaW5hcHAiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiMTkwOWFhMjgtNzc4Yi00MTFiLWI4N2YtMDExOWNlNDAxYzEwIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoicG9zdG1hbiIsInNlc3Npb25fc3RhdGUiOiJhNThlMjQxYi1hNmYyLTQzMzctYWRkMi1lNzM5ZjczNmQ1NTgiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIi8qIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ0YXJjaW5hcHAuZW50aXRpZXMuZmllbGRzLnZhbGlkRnJvbURhdGVUaW1lLnVwZGF0ZSIsImRlZmF1bHQtcm9sZXMtdGFyY2luYXBwIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiIsInRhcmNpbmFwcC5tZW1iZXIiXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoiYTU4ZTI0MWItYTZmMi00MzM3LWFkZDItZTczOWY3MzZkNTU4IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInJvbGVzIjpbInRhcmNpbmFwcC5lbnRpdGllcy5maWVsZHMudmFsaWRGcm9tRGF0ZVRpbWUudXBkYXRlIiwiZGVmYXVsdC1yb2xlcy10YXJjaW5hcHAiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwidGFyY2luYXBwLm1lbWJlciJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ1c2VyLWJhc2ljLXZlcmlmaWVkLW1lbWJlci0xIiwiZ2l2ZW5fbmFtZSI6IiIsImZhbWlseV9uYW1lIjoiIn0.CojiA9ShXSmOm5yTlIl2W3sZqKbvFZbsVAatqLXguYKVFcDhR7oH4BcU9rNs_x1PVqKZwq4gdwMvBNGYJ1Q2vtvWhGNdhgtbYKwvt4TPCWaHZ51QerBA0Kk8q5n3xeqgjZ93eft5rG9aFeaJtVsx0DfMWK1DbrjfXawRO9Te4GEPJgMkm_QSZXgOWkNI2rqfn45YvGr4lXxAH3iRXGbS-8rmFg1RnOgPAeTS-OoHKxSCO_Pa1KZSEi5ZeayY5_KS4GPg_7xnc0e9ltbq1U_yx8k4VfF_hb0TiMoC9zt6lrEUGWme4zQ1VzHIwBrnDvGMmhXTP_LAysz4Q1_MDtCTyw",
    "requestPayload": {
        "ownerUsersCount": 0,
        "ownerGroupsCount": 0,
        "validFromDateTime": "2023-10-20T21:54:06.988Z"
    },
    "originalRecord": {
        "id": "e613c7d0-3ea4-4815-80b6-eeb7e6f37b3e",
        "kind": "book",
        "name": "Karamazov Brothers",
        "slug": "karamazov-brothers",
        "visibility": "private",
        "ownerUsers": [
            "1909aa28-778b-411b-b87f-0119ce401c10"
        ],
        "ownerGroups": [],
        "ownerUsersCount": 1,
        "ownerGroupsCount": 0,
        "lastUpdatedBy": "1909aa28-778b-411b-b87f-0119ce401c10",
        "createdBy": "1909aa28-778b-411b-b87f-0119ce401c10",
        "version": 3,
        "idempotencyKey": "3678437ad111f82704f6a54954a1b96c105125264cb7e81e95ffca44986c307a",
        "creationDateTime": "2023-10-20T21:26:06.988Z",
        "lastUpdatedDateTime": "2023-10-20T21:31:56.937Z",
        "author": "Dostoyevski"
    }
}
```
**Additional Notes:**
- The provided input demonstrates a PATCH request, but similar input structures apply to GET, POST, and PUT requests as well.
- The requestPayload is particularly important when creating new records, as it contains essential data.
- Policies dynamically evaluate and make decisions based on these input parameters, ensuring secure and compliant interactions within the Entity Persistence Service.


### Policy Execution Output
* For authentication policies, application returns either `"allow": true` or `"allow": false` in the request body, according to the result of the policy.
* For field control policies application returns a response body similar to the following:
    ```json
    {
        "which_fields_forbidden_for_create": [
            "visibility",
            "version",
            "idempotencyKey",
            "application",
            "creationDateTime",
            "slug",
            "lastUpdatedDateTime",
            "lastUpdatedBy",
            "createdBy",
            "validFromDateTime",
            "validUntilDateTime",
            "ownerUsers"
        ],
        "which_fields_forbidden_for_finding": [
            "visibility",
            "version",
            "idempotencyKey",
            "application"
        ],
        "which_fields_forbidden_for_update": [
            "visibility",
            "version",
            "idempotencyKey",
            "application",
            "kind",
            "slug",
            "creationDateTime",
            "lastUpdatedDateTime",
            "lastUpdatedBy",
            "createdBy",
            "validUntilDateTime"
        ]
    }
    ```



# Policies
To access the details of each policy, you can refer to the policy's README.
1. [countEntities](./policies/auth/routes/countEntities/README.md)
2. [createEntity](./policies/auth/routes/createEntity/README.md)
3. [deleteEntityById](./policies/auth/routes/deleteEntityById/README.md)
4. [findEntities](./policies/auth/routes/findEntities/README.md)
5. [findEntityById](./policies/auth/routes/findEntityById/README.md)
6. [replaceEntityById](./policies/auth/routes/replaceEntityById/README.md)
7. [updateAllEntities](./policies/auth/routes/updateAllEntities/README.md)
8. [updateEntityById](./policies/auth/routes/updateEntityById/README.md)

# Setting Up the Development Environment
Get the OPA extension for Visual Studio Code (VSCode). This extension simplifies local OPA policy testing by automatically downloading and installing the OPA binary. It's a handy tool to ensure your policies work smoothly within your development environment, enhancing security and compliance for your applications.  
  
**Sample policy input**
policy input is a json file in the following structure
```json
{
    "httpMethod": "GET",
    "requestPath": "/generic-entities",
    "queryParams": {},
    "encodedJwt": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ1ZGtwaElQVFB1X0tpb28zWWlxYnFESS1IYlpVVWZieHVpMFRuWjRmanVnIn0.eyJleHAiOjE2OTEzMzA2OTYsImlhdCI6MTY5MTMzMDM5NiwianRpIjoiYWY4ZmMyZDctMjczOS00ZGYzLThhMTItMzkwMzVmZTY2YzM1IiwiaXNzIjoiaHR0cHM6Ly90YXJjaW5hcHAtaWRtLWtleWNsb2FrLnRvdjNxbS5lYXN5cGFuZWwuaG9zdC9yZWFsbXMvdGFyY2luYXBwIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjczMGVjODg2LThhN2YtNGZlNS04OTZkLWJjNWY0YzgyODE2MyIsInR5cCI6IkJlYXJlciIsImF6cCI6InBvc3RtYW4iLCJzZXNzaW9uX3N0YXRlIjoiMGQwYTUxY2UtMDkzMC00MGU5LWFkMjgtMWRlMWU0ZWNkZTdhIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL3d3dy5nZXRwb3N0bWFuLmNvbSJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy10YXJjaW5hcHAiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwidGFyY2luYXBwLm1lbWJlciJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiIwZDBhNTFjZS0wOTMwLTQwZTktYWQyOC0xZGUxZTRlY2RlN2EiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6Ikt1cnNhdCBUb2twdW5hciIsInByZWZlcnJlZF91c2VybmFtZSI6Imt1cnNhdHRva3BpbmFyIiwiZ2l2ZW5fbmFtZSI6Ikt1cnNhdCIsImZhbWlseV9uYW1lIjoiVG9rcHVuYXIiLCJlbWFpbCI6Imt1cnNhdHRva3BpbmFyQGdtYWlsLmNvbSJ9.nHBtP1-dLpjHWeCCB8FBaVNA4htYH0_BKBm6vB_rNS_a2e8xC_qQ2OtBogQsY42gd1S9d763a84OBWr3iF_pzJElMRuvdexXwQpu8eQ5YzvZyLrVeVGovM-Ep-EeeHRao0zj_92_E6SvlwBwqhNhXBdZ5Q6qLJuIuAxRfz_QMG4F67usuP4Fmmjw6fHddaJXJaLI8yKR5gOP1sPDpoS-acf1SRJipeuZzdbuEHvr5n9dP5YN8uD4_7DWa7A9zcM-2Z1jW3ij7USIugn7xxX4uschUFQQ6B48IxG145gq8N1MuVddQIvb5jOkRYuvjw_s3kXxfA1s3CI7JrEoCUffrA",
    "requestPayload": {
        "name": "Believe Yourself!",
        "author": "J. Martin Doe",
        "ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "ownerGroups":["group-1"],
        "validFromDateTime": "2019-10-12T07:20:50.52Z",
        "validUntilDateTime": null
    },
    "originalRecord": {
        "id": "0331c4d7-1408-4078-8e92-5169a55a12c5",
        "kind": "book",
        "name": "Believe Yourself!",
        "author": "J. Doe",
        "visibility": "private",
        "ownerUsers": ["ebe92b0c-bda2-49d0-99d0-feb538aa7db6"],
        "ownerGroups":["group-1"],
        "validFromDateTime": "2019-10-12T07:20:50.52Z",
        "validUntilDateTime": null
    }
}
```

## Role Structure in Tarcinapp

Tarcinapp supports a flexible, fine-grained role system that governs access across resources and fields. Roles are defined using a consistent naming convention that allows system administrators to grant permissions at both operation and field levels.

### Role Name Prefix (`tarcinapp.`)

Each role begins with an application-specific prefix, such as `tarcinapp.`. This prefix is a configurable application short code, designed to support scenarios where a single user may have different roles across multiple Tarcinapp instances.

### Operation-Level Roles

These roles control access to operations on resources such as entities, lists and reactions.

**Format:**
```
<app-code>[.<scope>][.<operation>].<level>
```

- **app-code**: Application-specific prefix (e.g., `tarcinapp`)
- **scope**: Resource domain. If not specified in the role name, it means that the role is valid for all scopes.
  Examples: `records`, `entities`, `lists`, `reactions`, `entity-reactions`, `list-reactions`
- **operation**: (optional) Operation being granted  
  Examples: `create`, `update`, `updateall`, `find`, `count`, `delete`  
  If omitted, the role grants all operations under the scope.
- **level**: Access tier  
  Examples: `admin`, `editor`, `member`, `visitor`

**Examples:**

| Role | Meaning |
|------|---------|
| `tarcinapp.admin` | Admin access to all operations |
| `tarcinapp.records.admin` | Admin access to all record operations |
| `tarcinapp.entities.create.editor` | Editor can create entities |
| `tarcinapp.lists.find.member` | Member can query (read) lists |
| `tarcinapp.reactions.delete.admin` | Admin can delete reactions |

### Field-Level Roles

These roles allow precise control over access to individual fields within records.

**Format:**
```
<app-code>.<scope>.fields.<fieldname>.<operation>
```

- **app-code**: Application-specific prefix (e.g., `tarcinapp`)
- **scope**: Resource domain (same as above)
- **fieldname**: Name of the field (e.g., `_visibility`, `_createdDateTime`)
- **operation**:  
  Options: `find`, `create`, `update`, `manage`  
  `manage` grants all permissions on the field.

**Examples:**

| Role | Meaning |
|------|---------|
| `tarcinapp.entities.fields._visibility.find` | Can read the `_visibility` field of entities |
| `tarcinapp.records.fields._createdDateTime.update` | Can update `_createdDateTime` on records |
| `tarcinapp.lists.fields._viewerGroups.manage` | Full access to `_viewerGroups` field on lists |

### Design Benefits

- Consistency: Predictable structure makes it easy to understand and manage
- Modularity: Different scopes for different resource types
- Flexibility: Field-level and operation-level access can be independently controlled
- Multi-Tenant Ready: Role prefix allows isolation across Tarcinapp instances


## Structuring the JWT Token (Keycloak Guide)
Policies within entity-persistence-policies search for the `roles` field within the JWT token, specifically under the `payload` section. However, in the default configuration of Keycloak, the roles are nested under `realm_access.roles`. To align them with the `payload` section, you must create a custom 'Role Mapper' in Keycloak. This mapper allows you to restructure the JWT token during the token issuance process. Here's how to do it:
1. Log in to your Keycloak admin console.
2. Choose the desired realm from the top-left drop-down menu.
3. Navigate to 'Clients' in the left-hand menu and select your client.
4. Access the 'Dedicated Scopes' tab.
5. Click on the {client-name}-dedicated.
6. Go to the 'Mappers' tab.
7. Click 'Add mappers.'
8. Select 'By Configuration.'
    * Name: Provide a clear name for your mapper (e.g., 'Realm Role Mapper').
    * Mapper Type: Choose 'User Realm Role.'
    * Token Claim Name: Set it to your desired name for roles in the payload (e.g., 'roles').
    * Multivalued: Select 'ON.'
    * Keep other settings as they are or adjust them based on your specific needs.
9. Click 'Save' to save the mapper.

Now, when a user logs in and requests an access token, the custom mapper will come into effect, moving the roles directly under the `payload` section with the key `roles`.