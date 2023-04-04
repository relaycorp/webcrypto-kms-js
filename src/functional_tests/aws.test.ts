import { KMSClient } from '@aws-sdk/client-kms';

import { AwsKmsRsaPssProvider } from '../lib/aws/AwsKmsRsaPssProvider';
import { PLAINTEXT } from '../testUtils/stubs';
import {
  NODEJS_CRYPTO,
  RSA_PSS_CREATION_ALGORITHM,
  RSA_PSS_SIGN_ALGORITHM,
} from '../testUtils/webcrypto';

const CLIENT = new KMSClient({
  credentials: { accessKeyId: 'accessKeyId', secretAccessKey: 'secretAccessKey' },
  endpoint: 'http://localhost:8080',
  region: 'eu-west-2',
});

test('AWS KMS', async () => {
  const provider = new AwsKmsRsaPssProvider(CLIENT);
  const keyPair = (await provider.generateKey(RSA_PSS_CREATION_ALGORITHM, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const signature = await provider.sign(RSA_PSS_SIGN_ALGORITHM, keyPair.privateKey, PLAINTEXT);

  await expect(
    NODEJS_CRYPTO.subtle.verify(RSA_PSS_SIGN_ALGORITHM, keyPair.publicKey, signature, PLAINTEXT),
  ).resolves.toBe(true);
});
