# WebCrypto-compatible client for Key Management Services like GCP KMS

This library extends [`webcrypto-core`](https://www.npmjs.com/package/webcrypto-core) to abstract the communication with KMSs, allowing you to use the same code to communicate with different KMSs. We currently support [GCP KMS](https://cloud.google.com/security-key-management) and [AWS KMS](https://aws.amazon.com/kms/), and we welcome PRs to support additional KMSs.

This is an alternative to:

- The [Key Management Interoperability Protocol (KMIP)](https://en.wikipedia.org/wiki/Key_Management_Interoperability_Protocol), if you don't want to run another server.
- [PKCS#11](https://en.wikipedia.org/wiki/PKCS_11), if you prefer to use official cloud SDKs instead of C libraries. This configures authentication automatically, and makes it possible to use telemetry.

## Usage

The library is available on NPM as [`@relaycorp/webcrypto-kms`](https://www.npmjs.com/package/@relaycorp/webcrypto-kms), and you can install it as follows:

```
npm i @relaycorp/webcrypto-kms
```

### Initialising the private key store

The configuration of the adapter is done via environment variables, so the actual initialisation of the store is done with a simple function call:

```typescript
import { initKmsProviderFromEnv, KmsRsaPssProvider } from '@relaycorp/webcrypto-kms';

async function init(): Promise<KmsRsaPssProvider> {
  return initKmsProviderFromEnv(process.env.KMS_ADAPTER);
}
```

`initKmsProviderFromEnv()` can be called with `'AWS'` or `'GCP'`.

The following environment variables must be defined depending on the adapter:

- AWS adapter:
  - [`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`](https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/loading-node-credentials-environment.html) (optional when running on AWS infrastructure).
  - `AWS_KMS_ENDPOINT` (optional when running on AWS infrastructure).
  - `AWS_KMS_REGION` (optional when running on AWS infrastructure).
- GCP adapter:
  - [`GOOGLE_APPLICATION_CREDENTIALS`](https://cloud.google.com/docs/authentication/getting-started) (optional when running on GCP infrastructure).
  - `GCP_KMS_KEYRING` (required).
  - `GCP_KMS_LOCATION` (required; e.g., `europe-west3`).
  - `GCP_KMS_PROTECTION_LEVEL` (required; i.e., `SOFTWARE` or `HSM`).

## Additional methods

`KmsRsaPssProvider` exposes the following additional methods:

- `destroyKey(privateKey)`: Destroys the specified private key.
- `close()`: Closes the underlying network resources, when the provider is no longer needed.

## Integration test suite

The integration tests aren't currently run on CI, and can be run with `npm run test:integration:local`.

All GCP resources will be created within the same project where the service account lives. The GCP service account should be allowed to manage KMS resources.

Before running the AWS KMS tests, you need to start a mock AWS KMS server locally using docker:

```bash
docker run --rm -p 8080:8080 nsmithuk/local-kms
```

The test suite will automatically delete all the resources it created, except for those that can't be deleted (e.g., GPC KMS key rings). Existing resources are not modified. However, this may not always be true due to bugs, so **always create a brand new, temporary GCP project**.
