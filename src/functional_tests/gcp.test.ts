import { KeyManagementServiceClient } from '@google-cloud/kms';

import { initKmsProviderFromEnv, KmsRsaPssProvider } from '../index';
import { PLAINTEXT, verifyAsymmetricSignature } from './utils';
import { RSA_PSS_CREATION_ALGORITHM, RSA_PSS_SIGN_ALGORITHM } from '../testUtils/webcrypto';

if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  throw new Error('GOOGLE_APPLICATION_CREDENTIALS must be defined');
}

let provider: KmsRsaPssProvider;
let keyPair: CryptoKeyPair;
beforeAll(async () => {
  provider = await initKmsProviderFromEnv('GCP');
  await createKeyRingIfMissing(process.env.GCP_KMS_KEYRING!, process.env.GCP_KMS_LOCATION!);

  keyPair = await provider.generateKey(RSA_PSS_CREATION_ALGORITHM, true, ['sign', 'verify']);
});
afterAll(async () => {
  if (keyPair) {
    await provider?.destroyKey(keyPair.privateKey);
  }
  await provider?.close();
});

test('GCP KMS', async () => {
  const { publicKey, privateKey } = keyPair;

  const signature = await provider.sign(RSA_PSS_SIGN_ALGORITHM, privateKey, PLAINTEXT);

  await expect(verifyAsymmetricSignature(publicKey, signature, PLAINTEXT)).resolves.toBe(true);
});

export async function createKeyRingIfMissing(keyRingId: string, location: string): Promise<string> {
  const kmsClient = new KeyManagementServiceClient();
  const project = await kmsClient.getProjectId();
  const keyRingName = kmsClient.keyRingPath(project, location, keyRingId);
  try {
    await kmsClient.getKeyRing({ name: keyRingName });
  } catch (err) {
    if ((err as any).code !== 5) {
      throw err;
    }

    // Key ring was not found
    const locationPath = kmsClient.locationPath(project, location);
    await kmsClient.createKeyRing({ parent: locationPath, keyRingId });
  }

  await kmsClient.close();
  return keyRingName;
}
