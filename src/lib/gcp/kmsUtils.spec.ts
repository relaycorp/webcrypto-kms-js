import { KeyManagementServiceClient } from '@google-cloud/kms';

import { derPublicKeyToPem } from '../../testUtils/asn1';
import { getMockContext, getMockInstance } from '../../testUtils/jest';
import { catchPromiseRejection } from '../../testUtils/promises';
import { mockSleep } from '../../testUtils/timing';
import { KmsError } from '../KmsError';
import { retrieveKMSPublicKey, wrapGCPCallError } from './kmsUtils';

const sleepMock = mockSleep();

describe('retrieveKMSPublicKey', () => {
  const KMS_KEY_VERSION_NAME = 'projects/foo/key/42';

  test('Specified key version name should be honored', async () => {
    const kmsClient = makeKmsClient();

    await retrieveKMSPublicKey(KMS_KEY_VERSION_NAME, kmsClient);

    expect(kmsClient.getPublicKey).toHaveBeenCalledWith(
      expect.objectContaining({ name: KMS_KEY_VERSION_NAME }),
      expect.anything(),
    );
  });

  test('Public key should be output DER-serialized', async () => {
    const publicKeyDer = Buffer.from('This is a DER-encoded public key :wink:');
    const kmsClient = makeKmsClient(derPublicKeyToPem(publicKeyDer));

    const publicKey = await retrieveKMSPublicKey(KMS_KEY_VERSION_NAME, kmsClient);

    expect(publicKey).toBeInstanceOf(ArrayBuffer);
    expect(Buffer.from(publicKey as ArrayBuffer)).toEqual(publicKeyDer);
  });

  test('Public key export should time out after 300ms', async () => {
    const kmsClient = makeKmsClient();

    await retrieveKMSPublicKey(KMS_KEY_VERSION_NAME, kmsClient);

    expect(kmsClient.getPublicKey).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ timeout: 300 }),
    );
  });

  test('Public key export should be retried up to 3 times', async () => {
    const kmsClient = makeKmsClient();

    await retrieveKMSPublicKey(KMS_KEY_VERSION_NAME, kmsClient);

    expect(kmsClient.getPublicKey).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ maxRetries: 3 }),
    );
  });

  test('Retrieval should be retried after 500ms if key is pending generation', async () => {
    const publicKeyDer = Buffer.from('This is a DER-encoded public key :wink:');
    const kmsClient = makeKmsClient();
    const callError = new MockGCPError('Whoops', 'KEY_PENDING_GENERATION');
    getMockInstance(kmsClient.getPublicKey)
      .mockRejectedValueOnce(callError)
      .mockResolvedValueOnce([{ pem: derPublicKeyToPem(publicKeyDer) }]);

    const publicKey = await retrieveKMSPublicKey(KMS_KEY_VERSION_NAME, kmsClient);

    expect(kmsClient.getPublicKey).toHaveBeenCalledTimes(2);
    expect(sleepMock).toHaveBeenCalledWith(500);
    expect(getMockContext(kmsClient.getPublicKey).invocationCallOrder[0]).toBeLessThan(
      getMockContext(sleepMock).invocationCallOrder[0],
    );
    expect(getMockContext(kmsClient.getPublicKey).invocationCallOrder[1]).toBeGreaterThan(
      getMockContext(sleepMock).invocationCallOrder[0],
    );
    expect(Buffer.from(publicKey as ArrayBuffer)).toEqual(publicKeyDer);
  });

  test('Non-KEY_PENDING_GENERATION violations should be propagated immediately', async () => {
    const callError = new MockGCPError('Whoops', 'NOT-KEY_PENDING_GENERATION');
    const kmsClient = makeKmsClient(callError);

    await catchPromiseRejection(retrieveKMSPublicKey(KMS_KEY_VERSION_NAME, kmsClient), KmsError);

    expect(kmsClient.getPublicKey).toHaveBeenCalledTimes(1);
  });

  test('Any other errors should be wrapped', async () => {
    const callError = new Error('The service is down');
    const kmsClient = makeKmsClient(callError);

    const error = await catchPromiseRejection(
      retrieveKMSPublicKey(KMS_KEY_VERSION_NAME, kmsClient),
      KmsError,
    );

    expect(error.message).toStartWith('Failed to retrieve public key');
    expect(error.cause).toEqual(callError);
    expect(kmsClient.getPublicKey).toHaveBeenCalledTimes(1);
  });

  function makeKmsClient(
    publicKeyPemOrError: string | Error = 'pub key',
  ): KeyManagementServiceClient {
    const kmsClient = new KeyManagementServiceClient();
    jest.spyOn(kmsClient, 'getPublicKey').mockImplementation(async () => {
      if (publicKeyPemOrError instanceof Error) {
        throw publicKeyPemOrError;
      }
      return [{ pem: publicKeyPemOrError }, undefined, undefined];
    });
    return kmsClient;
  }
});

describe('wrapGCPCallError', () => {
  const gcpError = new Error('Someone talked about Bruno');

  test('Successful calls should resolve', async () => {
    const resolvedValue = 42;

    await expect(wrapGCPCallError(Promise.resolve(resolvedValue), '')).resolves.toEqual(
      resolvedValue,
    );
  });

  test('Failed calls should be wrapped in custom error', async () => {
    await expect(wrapGCPCallError(Promise.reject(gcpError), '')).rejects.toBeInstanceOf(KmsError);
  });

  test('Wrapping exception should use specified error message', async () => {
    const errorMessage = 'The error message';

    const error = await catchPromiseRejection(
      wrapGCPCallError(Promise.reject(gcpError), errorMessage),
      KmsError,
    );

    expect(error.message).toEqual(errorMessage);
  });

  test('Wrapped exception should be original one from GCP API client', async () => {
    const error = await catchPromiseRejection(
      wrapGCPCallError(Promise.reject(gcpError), ''),
      KmsError,
    );

    expect(error.cause).toEqual(gcpError);
  });
});

class MockGCPError extends Error {
  public readonly statusDetails: readonly any[];
  constructor(message: string, violationType: string) {
    super(message);

    this.statusDetails = [{ violations: [{ type: violationType }] }];
  }
}
