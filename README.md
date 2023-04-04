# WebCrypto-compatible client for Key Management Services like GCP KMS

This library extends [`webcrypto-core`](https://www.npmjs.com/package/webcrypto-core) to abstract the communication with KMSs (e.g., [GCP KMS](https://cloud.google.com/security-key-management)), allowing you to use the same code to communicate with different KMSs.

This is an alternative to the Key Management Interoperability Protocol (KMIP) and PKCS#11. TODO: Explain why.

### Integration test suite

The integration tests aren't currently run on CI, and can be run with `npm run test:integration:local`. Note that some environments variables must be set, and others are optional:

- GCP adapter:
  - [`GOOGLE_APPLICATION_CREDENTIALS`](https://cloud.google.com/docs/authentication/getting-started) (required), using a service account. All GCP resources will be created within the same project where the service account lives. The GCP service account should be allowed to manage KMS resources.
  - `GCP_KMS_KEYRING`.
  - `GCP_KMS_LOCATION` (e.g., `europe-west3`).

The test suite will automatically delete all the resources it created, except for those that can't be deleted (e.g., GPC KMS key rings). Existing resources are not modified. However, this may not always be true due to bugs, so **always create a brand new, temporary GCP project**.
