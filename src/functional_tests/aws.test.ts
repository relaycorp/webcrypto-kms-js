import { constants, createVerify, webcrypto } from 'crypto';
import { KMSClient, VerifyCommand, SigningAlgorithmSpec, MessageType } from '@aws-sdk/client-kms';

import { derSerializePublicKey, NODEJS_CRYPTO } from '../testUtils/webcrypto';
import { derPublicKeyToPem } from '../testUtils/asn1';
import { initKmsProviderFromEnv, KmsRsaPssProvider } from '../index';
import {
  KEY_USAGES,
  RSA_PSS_CREATION_ALGORITHM,
  RSA_PSS_IMPORT_ALGORITHM,
  RSA_PSS_SIGN_ALGORITHM,
} from '../testUtils/webcrypto';
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
  keyPair = await provider.generateKey(RSA_PSS_CREATION_ALGORITHM, true, KEY_USAGES);
});
afterAll(async () => {
  if (keyPair) {
    await provider?.destroyKey(keyPair.privateKey);
  }
  await provider?.close();
});

describe('AWS KMS', () => {
  test('Peculiar WebCrypto verification', async () => {
    const { publicKey, privateKey } = keyPair;

    const signature = await provider.sign(RSA_PSS_SIGN_ALGORITHM, privateKey, PLAINTEXT);

    await expect(verifyAsymmetricSignature(publicKey, signature, PLAINTEXT)).resolves.toBe(true);
  });

  test('Node.js WebCrypto verification', async () => {
    const { publicKey, privateKey } = keyPair;

    const signature = await provider.sign(RSA_PSS_SIGN_ALGORITHM, privateKey, PLAINTEXT);

    const publicKeySpki = await NODEJS_CRYPTO.subtle.exportKey('spki', publicKey);
    const nodePublicKey = await webcrypto.subtle.importKey(
      'spki',
      publicKeySpki,
      RSA_PSS_IMPORT_ALGORITHM,
      true, // extractable
      ['verify'], // key usages for public key
    );
    await expect(
      webcrypto.subtle.verify(
        RSA_PSS_SIGN_ALGORITHM,
        nodePublicKey, // Use the re-imported key
        signature,
        PLAINTEXT,
      ),
    ).resolves.toBeTrue();
  });

  test('Node.js verification', async () => {
    const { publicKey, privateKey } = keyPair;

    const signature = await provider.sign(RSA_PSS_SIGN_ALGORITHM, privateKey, PLAINTEXT);

    const verify = createVerify('sha256');
    verify.update(PLAINTEXT);
    verify.end();
    const publicKeyDer = await derSerializePublicKey(publicKey);
    const publicKeyPem = derPublicKeyToPem(publicKeyDer);
    expect(
      verify.verify(
        { key: publicKeyPem, padding: constants.RSA_PKCS1_PSS_PADDING },
        new Uint8Array(signature),
      ),
    ).toBeTrue();
  });

  test('AWS SDK verification', async () => {
    const { privateKey } = keyPair;

    const signature = await provider.sign(RSA_PSS_SIGN_ALGORITHM, privateKey, PLAINTEXT);

    const arnBuffer = (await provider.exportKey('raw', privateKey)) as ArrayBuffer;
    const keyArn = Buffer.from(arnBuffer).toString();
    const verifyCommand = new VerifyCommand({
      KeyId: keyArn,
      Message: PLAINTEXT,
      MessageType: MessageType.RAW,
      Signature: new Uint8Array(signature),
      SigningAlgorithm: SigningAlgorithmSpec.RSASSA_PSS_SHA_256,
    });
    const client = new KMSClient({
      endpoint: process.env.AWS_KMS_ENDPOINT,
      region: process.env.AWS_KMS_REGION,
    });
    const response = await client.send(verifyCommand);
    expect(response.SignatureValid).toBe(true);
  });
});
