import { KeyManagementServiceClient } from '@google-cloud/kms';
import { calculate as calculateCRC32C } from 'fast-crc32c';
import { CryptoKey } from 'webcrypto-core';

import { catchPromiseRejection } from '../../testUtils/promises';
import { bufferToArrayBuffer } from '../utils/buffer';
import { KmsError } from '../KmsError';
import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';
import { GcpKmsRsaPssProvider } from './GcpKmsRsaPssProvider';
import { mockSleep } from '../../testUtils/timing';
import { derPublicKeyToPem } from '../../testUtils/asn1';
import { getMockContext, getMockInstance } from '../../testUtils/jest';

const ALGORITHM = { name: 'RSA-PSS', saltLength: 32 };

const sleepMock = mockSleep();

let privateKey: GcpKmsRsaPssPrivateKey;
beforeAll(async () => {
  privateKey = new GcpKmsRsaPssPrivateKey(
    '/the/path/key-name',
    'SHA-256',
    new GcpKmsRsaPssProvider(null as any),
  );
});

describe('hashingAlgorithms', () => {
  test('Only SHA-256 and SHA-512 should be supported', async () => {
    const provider = new GcpKmsRsaPssProvider(null as any);

    expect(provider.hashAlgorithms).toEqual(['SHA-256', 'SHA-512']);
  });
});

describe('onGenerateKey', () => {
  test('Method should not be supported', async () => {
    const provider = new GcpKmsRsaPssProvider(null as any);

    await expect(provider.onGenerateKey()).rejects.toThrowWithMessage(
      KmsError,
      'Key generation is unsupported',
    );
  });
});

describe('onImportKey', () => {
  test('Method should not be supported', async () => {
    const provider = new GcpKmsRsaPssProvider(null as any);

    await expect(provider.onImportKey()).rejects.toThrowWithMessage(
      KmsError,
      'Key import is unsupported',
    );
  });
});

describe('onSign', () => {
  const PLAINTEXT = bufferToArrayBuffer(Buffer.from('the plaintext'));
  const SIGNATURE = Buffer.from('the signature');

  test('Non-KMS key should be refused', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient);
    const invalidKey = CryptoKey.create({ name: 'RSA-PSS' }, 'private', true, ['sign']);

    await expect(provider.sign(ALGORITHM, invalidKey, PLAINTEXT)).rejects.toThrowWithMessage(
      KmsError,
      `Cannot sign with key of unsupported type (${invalidKey.constructor.name})`,
    );

    expect(kmsClient.asymmetricSign).not.toHaveBeenCalled();
  });

  test('Signature should be output', async () => {
    const kmsClient = makeKmsClient({ signature: SIGNATURE });
    const provider = new GcpKmsRsaPssProvider(kmsClient);

    const signature = await provider.sign(ALGORITHM, privateKey, PLAINTEXT);

    expect(Buffer.from(signature)).toEqual(SIGNATURE);
  });

  test('Correct key path should be used', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient);

    await provider.sign(ALGORITHM, privateKey, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.objectContaining({ name: privateKey.kmsKeyVersionPath }),
      expect.anything(),
    );
  });

  test('Correct plaintext should be passed', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient);

    await provider.sign(ALGORITHM, privateKey, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.toSatisfy((req) => Buffer.from(req.data).equals(Buffer.from(PLAINTEXT))),
      expect.anything(),
    );
  });

  test('Plaintext CRC32C checksum should be passed to KMS', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient);

    await provider.sign(ALGORITHM, privateKey, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.objectContaining({ dataCrc32c: { value: calculateCRC32C(Buffer.from(PLAINTEXT)) } }),
      expect.anything(),
    );
  });

  test('KMS should verify signature CRC32C checksum from the client', async () => {
    const provider = new GcpKmsRsaPssProvider(makeKmsClient({ verifiedSignatureCRC32C: false }));

    await expect(provider.sign(ALGORITHM, privateKey, PLAINTEXT)).rejects.toThrowWithMessage(
      KmsError,
      'KMS failed to verify plaintext CRC32C checksum',
    );
  });

  test('Signature CRC32C checksum from the KMS should be verified', async () => {
    const provider = new GcpKmsRsaPssProvider(
      makeKmsClient({ signatureCRC32C: calculateCRC32C(SIGNATURE) - 1 }),
    );

    await expect(provider.sign(ALGORITHM, privateKey, PLAINTEXT)).rejects.toThrowWithMessage(
      KmsError,
      'Signature CRC32C checksum does not match one received from KMS',
    );
  });

  test('KMS should sign with the specified key', async () => {
    const kmsKeyVersionName = `not-${privateKey.kmsKeyVersionPath}`;
    const provider = new GcpKmsRsaPssProvider(makeKmsClient({ kmsKeyVersionName }));

    await expect(provider.sign(ALGORITHM, privateKey, PLAINTEXT)).rejects.toThrowWithMessage(
      KmsError,
      `KMS used the wrong key version (${kmsKeyVersionName})`,
    );
  });

  test('Request should time out after 3 seconds', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient);

    await provider.sign(ALGORITHM, privateKey, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ timeout: 3_000 }),
    );
  });

  test('Request should be retried', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient);

    await provider.sign(ALGORITHM, privateKey, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ maxRetries: 10 }),
    );
  });

  test('API call errors should be wrapped', async () => {
    const callError = new Error('Bruno. There. I said it.');
    const provider = new GcpKmsRsaPssProvider(makeKmsClient(callError));

    const error = await catchPromiseRejection(
      provider.sign(ALGORITHM, privateKey, PLAINTEXT),
      KmsError,
    );

    expect(error.message).toStartWith('KMS signature request failed');
    expect(error.cause).toEqual(callError);
  });

  describe('Algorithm parameters', () => {
    test.each([32, 64])('Salt length of %s should be accepted', async (saltLength) => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient);
      const algorithm = { ...ALGORITHM, saltLength };

      await provider.sign(algorithm, privateKey, PLAINTEXT);
    });

    test.each([20, 48])('Salt length of %s should be refused', async (saltLength) => {
      // 20 and 48 are used by SHA-1 and SHA-384, respectively, which are unsupported
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient);
      const algorithm = { ...ALGORITHM, saltLength };

      await expect(provider.sign(algorithm, privateKey, PLAINTEXT)).rejects.toThrowWithMessage(
        KmsError,
        `Unsupported salt length of ${saltLength} octets`,
      );
    });
  });

  interface KMSSignatureResponse {
    readonly signature: Buffer;
    readonly signatureCRC32C: number;
    readonly verifiedSignatureCRC32C: boolean;
    readonly kmsKeyVersionName: string;
  }

  function makeKmsClient(
    responseOrError: Partial<KMSSignatureResponse> | Error = {},
  ): KeyManagementServiceClient {
    const kmsClient = new KeyManagementServiceClient();
    jest.spyOn(kmsClient, 'asymmetricSign').mockImplementation(async () => {
      if (responseOrError instanceof Error) {
        throw responseOrError;
      }

      const signature = responseOrError.signature ?? SIGNATURE;
      const signatureCrc32c = responseOrError.signatureCRC32C ?? calculateCRC32C(signature);
      const response = {
        name: responseOrError.kmsKeyVersionName ?? privateKey.kmsKeyVersionPath,
        signature,
        signatureCrc32c: { value: signatureCrc32c.toString() },
        verifiedDataCrc32c: responseOrError.verifiedSignatureCRC32C ?? true,
      };
      return [response, undefined, undefined];
    });
    return kmsClient;
  }
});

describe('onVerify', () => {
  test('Method should not be supported', async () => {
    const provider = new GcpKmsRsaPssProvider(null as any);

    await expect(provider.onVerify()).rejects.toThrowWithMessage(
      KmsError,
      'Signature verification is unsupported',
    );
  });
});

describe('onExportKey', () => {
  test.each(['jwt', 'pkcs8', 'raw'] as readonly KeyFormat[])(
    '%s export should be unsupported',
    async (format) => {
      const provider = new GcpKmsRsaPssProvider(null as any);

      await expect(provider.onExportKey(format, privateKey)).rejects.toThrowWithMessage(
        KmsError,
        'Private key cannot be exported',
      );
    },
  );

  // noinspection JSMismatchedCollectionQueryUpdate
  describe('SPKI', () => {
    test('Specified key version name should be honored', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient);

      await provider.exportKey('spki', privateKey);

      expect(kmsClient.getPublicKey).toHaveBeenCalledWith(
        expect.objectContaining({ name: privateKey.kmsKeyVersionPath }),
        expect.anything(),
      );
    });

    test('Public key should be output DER-serialized', async () => {
      const publicKeyDer = Buffer.from('This is a DER-encoded public key :wink:');
      const kmsClient = makeKmsClient(derPublicKeyToPem(publicKeyDer));
      const provider = new GcpKmsRsaPssProvider(kmsClient);

      const publicKey = await provider.exportKey('spki', privateKey);

      expect(publicKey).toBeInstanceOf(ArrayBuffer);
      expect(Buffer.from(publicKey as ArrayBuffer)).toEqual(publicKeyDer);
    });

    test('Public key export should time out after 300ms', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient);

      await provider.exportKey('spki', privateKey);

      expect(kmsClient.getPublicKey).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ timeout: 300 }),
      );
    });

    test('Public key export should be retried up to 3 times', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient);

      await provider.exportKey('spki', privateKey);

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
      const provider = new GcpKmsRsaPssProvider(kmsClient);

      const publicKey = await provider.exportKey('spki', privateKey);

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
      const provider = new GcpKmsRsaPssProvider(kmsClient);

      await catchPromiseRejection(provider.exportKey('spki', privateKey), KmsError);

      expect(kmsClient.getPublicKey).toHaveBeenCalledTimes(1);
    });

    test('Any other errors should be wrapped', async () => {
      const callError = new Error('The service is down');
      const kmsClient = makeKmsClient(callError);
      const provider = new GcpKmsRsaPssProvider(kmsClient);

      const error = await catchPromiseRejection(provider.exportKey('spki', privateKey), KmsError);

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

    class MockGCPError extends Error {
      public readonly statusDetails: readonly any[];

      constructor(message: string, violationType: string) {
        super(message);

        this.statusDetails = [{ violations: [{ type: violationType }] }];
      }
    }
  });

  test('Non-KMS key should be refused', async () => {
    const provider = new GcpKmsRsaPssProvider(null as any);
    const invalidKey = new CryptoKey();

    await expect(provider.onExportKey('spki', invalidKey)).rejects.toThrowWithMessage(
      KmsError,
      'Key is not managed by KMS',
    );
  });
});
