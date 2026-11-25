# Sitetracker MCP v0.1.0 — development candidate

Not approved for deployment. Build and tests have not yet been run; no live Salesforce calls have been made. Based on upstream `53afc53feaabc2c318909631af937cf6ba27dd0a`.

The default entry point now exposes three limited read-only tools: object API-name search, approved-field describe and simple bounded record samples. The remaining upstream tools are still present in source for reference but not registered. Aggregate/SOSL, raw filters/order, relationship paths and Apex/log access are deferred until separately implemented and reviewed. A narrow REST adapter deliberately avoids passing a general-purpose authenticated Salesforce connection to the tool layer. It checks the token origin, authenticated user and org, and `Organization.IsSandbox` before exposing results. No generic API or write interface exists in this entry point.

## Operator configuration (only after S02 verification)

Use company-approved secret storage and runtime injection; do not commit secrets or include them in image builds. Required settings (names only):

- `SITETRACKER_MODE`: `sandbox-read-only`
- `SALESFORCE_CONNECTION_TYPE`: `OAuth_2.0_Client_Credentials`
- `SALESFORCE_INSTANCE_URL`: exact HTTPS sandbox My Domain origin, no trailing slash
- `SITETRACKER_ORG_ID`, `SITETRACKER_USER_ID`: approved Salesforce IDs
- `SALESFORCE_API_VERSION`: approved API version, e.g. `62.0`
- `SITETRACKER_ALLOWED_FIELDS`: JSON map from approved object API names to arrays of approved direct field API names
- `SALESFORCE_CLIENT_ID` and `SALESFORCE_CLIENT_SECRET`: supplied securely at runtime

Synthetic policy example: `{"Example__c":["Id","Name"]}`. Missing/invalid config means no tools advertised or callable. The exact OAuth userinfo scope and Organization query permissions need verification in the approved sandbox; inability to verify fails closed. Do not weaken identity checks to make connectivity work. No production profile implemented.

## Build and test, without any org credentials

From this checkout with approved Node 22+ and npm tooling:

```sh
npm ci --ignore-scripts
npm run build
npm test
```

The new tests use synthetic mocked fetch responses; no network is needed for the tests after dependencies are installed. Do not launch the development candidate with real credentials until the tests and security review are complete. In particular, the MCP dispatch/list integration, concurrency/timeout, audit output and identity API compatibility need further verification.
