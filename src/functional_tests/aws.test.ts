import { initKmsProviderFromEnv, KmsRsaPssProvider } from '../index';
import { RSA_PSS_CREATION_ALGORITHM, RSA_PSS_SIGN_ALGORITHM } from '../testUtils/webcrypto';
import { PLAINTEXT, verifyAsymmetricSignature } from './utils';

let provider: KmsRsaPssProvider;
let keyPair: CryptoKeyPair;
beforeAll(async () => {
  provider = await initKmsProviderFromEnv('AWS');
  keyPair = await provider.generateKey(RSA_PSS_CREATION_ALGORITHM, true, ['sign', 'verify']);
});
afterAll(async () => {
  if (keyPair) {
    await provider?.destroyKey(keyPair.privateKey);
  }
  await provider?.close();
});

test('AWS KMS', async () => {
  const { publicKey, privateKey } = keyPair;

  const signature = await provider.sign(RSA_PSS_SIGN_ALGORITHM, privateKey, PLAINTEXT);

  await expect(verifyAsymmetricSignature(publicKey, signature, PLAINTEXT)).resolves.toBe(true);
});
