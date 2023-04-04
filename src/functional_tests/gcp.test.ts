import { KeyManagementServiceClient } from '@google-cloud/kms';
import { constants, createVerify } from 'crypto';

import { initKmsProviderFromEnv, KmsRsaPssProvider } from '../index';
import { derPublicKeyToPem } from '../testUtils/asn1';
import { createKeyRingIfMissing } from './gcpUtils';
import {
  derSerializePublicKey,
  RSA_PSS_CREATION_ALGORITHM,
  RSA_PSS_SIGN_ALGORITHM,
} from '../testUtils/webcrypto';

const PLAINTEXT = Buffer.from('this is the plaintext');

if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  throw new Error('GOOGLE_APPLICATION_CREDENTIALS must be defined');
}

let gcpProvider: KmsRsaPssProvider;
let keyPair: CryptoKeyPair;
beforeAll(async () => {
  gcpProvider = await initKmsProviderFromEnv('GCP');
  const kmsClient = new KeyManagementServiceClient();
  await createKeyRingIfMissing(
    process.env.GCP_KMS_KEYRING!,
    kmsClient,
    process.env.GCP_KMS_LOCATION!,
  );

  keyPair = await gcpProvider.generateKey(RSA_PSS_CREATION_ALGORITHM, true, ['sign', 'verify']);
});
afterAll(async () => {
  if (keyPair) {
    await gcpProvider?.destroyKey(keyPair.privateKey);
  }
  await gcpProvider?.close();
});

test('Lifecycle', async () => {
  const { publicKey, privateKey } = keyPair;

  const signature = await gcpProvider.sign(RSA_PSS_SIGN_ALGORITHM, privateKey, PLAINTEXT);

  await expect(verifyAsymmetricSignature(publicKey, signature, PLAINTEXT)).resolves.toBe(true);
});

async function verifyAsymmetricSignature(
  publicKey: CryptoKey,
  signature: ArrayBuffer,
  plaintext: Buffer,
): Promise<boolean> {
  const verify = createVerify('sha256');
  verify.update(plaintext);
  verify.end();

  const publicKeyDer = await derSerializePublicKey(publicKey);
  return verify.verify(
    { key: derPublicKeyToPem(publicKeyDer), padding: constants.RSA_PKCS1_PSS_PADDING },
    new Uint8Array(signature),
  );
}
