# WebCrypto-compatible client for Key Management Services like GCP KMS

This library extends [`webcrypto-core`](https://www.npmjs.com/package/webcrypto-core) to abstract the communication with KMSs (e.g., [GCP KMS](https://cloud.google.com/security-key-management)), allowing you to use the same code to communicate with different KMSs.

This is an alternative to the Key Management Interoperability Protocol (KMIP) and PKCS#11. TODO: Explain why.
