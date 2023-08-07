# entity-persistence-gateway-policies
On vscode download OPA extension. This extension will allow you install the OPA binary to test the policies locally. 
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

Policies are looking for roles field under the jwt token right under the payload field. In the default configuration of keycloak, the roles are under the realm_access.roles field. So, you need to map roles to the right under the payload field. To do that, you need to add a mapper to the client in keycloak.

Here is how to do it:
To modify the structure of the JWT token payload and move the roles directly under the payload instead of being nested under realm_access.roles, you'll need to create a custom "Role Mapper" in Keycloak. The Role Mapper allows you to manipulate the token claims during the token issuance process. Here's how you can achieve this:

Log in to your Keycloak admin console.
Select the desired realm from the drop-down menu on the top left.
Go to "Clients" from the left-hand menu and select your client.
Click on the "Dedicated Scopes" tab.
Click on the {client-name}-dedicated.
Click on the "Mappers" tab.
Click on the "Add mappers" button.

Name: Enter a descriptive name for your mapper (e.g., Custom Role Mapper).
Mapper Type: Select User Realm Role.
Token Claim Name: Set it to the desired name for the roles in the payload (e.g., roles).
Multivalued: Select ON.
Leave other settings as they are or adjust them according to your specific requirements.

Click "Save" to save the mapper.
Now, when a user logs in and requests an access token, the custom mapper will be applied, and the roles will be moved directly under the payload with the key roles.