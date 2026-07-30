# AWS Cognito 


### Cognito Identity Pool Misconfiguration

Cognito Identity Pools can give unauthenticated users temporary AWS credentials.

Flow:

```text
Web App → Cognito → Temporary Credentials → IAM Role → AWS Services
```

Find AWS info in JS/source:

* Identity Pool ID
* AWS Region
* DynamoDB table names

Get credentials from the **browser console**: ```AWS.config.credentials```

Look for: `accessKeyId` - `secretAccessKey` - `sessionToken`


```bash
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
```
then ```aws sts get-caller-identity``` Inside console

Enumerate permissions:

```bash
aws dynamodb list-tables
aws dynamodb scan --table-name <table>

aws s3 ls
aws lambda list-functions
```

Common vulnerability:

* Cognito guest role has excessive permissions.
* Client-side IDs (`localStorage`, parameters) are trusted.
* DynamoDB allows reading more data than intended.

---

Remember:

**The credentials are not the vulnerability — the IAM permissions are.**
