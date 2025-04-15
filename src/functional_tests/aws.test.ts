import { initKmsProviderFromEnv, KmsRsaPssProvider } from '../index';
import { RSA_PSS_CREATION_ALGORITHM, RSA_PSS_SIGN_ALGORITHM } from '../testUtils/webcrypto';
import { PLAINTEXT, verifyAsymmetricSignature } from './utils';

process.env.KMS_ADAPTER = 'AWS';
process.env.AWS_ACCESS_KEY_ID = 'access_key_id';
process.env.AWS_SECRET_ACCESS_KEY = 'secret_access_key';
process.env.AWS_KMS_ENDPOINT = 'http://127.0.0.1:8080';
process.env.AWS_KMS_REGION = 'eu-west-2';

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
