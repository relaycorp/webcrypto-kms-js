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
import { getMockContext, getMockInstance, mockSpy } from '../../testUtils/jest';
import { GcpKmsConfig, ProtectionLevel } from './GcpKmsConfig';
import {
  derSerializePublicKey,
  HASHING_ALGORITHM,
  HASHING_ALGORITHM_NAME,
  KEY_USAGES,
  RSA_PSS_CREATION_ALGORITHM,
  RSA_PSS_IMPORT_ALGORITHM,
  RSA_PSS_SIGN_ALGORITHM,
} from '../../testUtils/webcrypto';
import { PLAINTEXT, REAL_PUBLIC_KEYS, SIGNATURE } from '../../testUtils/stubs';

const mockStubUuid4 = '56e95d8a-6be2-4020-bb36-5dd0da36c181';
jest.mock('uuid4', () => {
  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => mockStubUuid4),
  };
});

const GCP_PROJECT = 'the-project';
const KMS_CONFIG: GcpKmsConfig = {
  keyRing: 'the-ring',
  location: 'westeros-east1',
  protectionLevel: 'SOFTWARE',
};

const sleepMock = mockSleep();

const KMS_KEY_VERSION_PATH = '/the/path/key-name';
const PRIVATE_KEY = new GcpKmsRsaPssPrivateKey(
  KMS_KEY_VERSION_PATH,
  HASHING_ALGORITHM_NAME,
  null as any,
);

describe('hashingAlgorithms', () => {
  test('Only SHA-256 and SHA-512 should be supported', async () => {
    const provider = new GcpKmsRsaPssProvider(null as any, KMS_CONFIG);

    expect(provider.hashAlgorithms).toEqual(['SHA-256', 'SHA-512']);
  });
});

describe('onGenerateKey', () => {
  const REAL_PUBLIC_KEY = REAL_PUBLIC_KEYS.gcp;

  const ALGORITHM = RSA_PSS_CREATION_ALGORITHM;

  let stubPublicKeySerialized: ArrayBuffer;
  beforeAll(async () => {
    stubPublicKeySerialized = bufferToArrayBuffer(REAL_PUBLIC_KEY);
  });

  const mockOnExportKey = mockSpy(
    jest.spyOn(GcpKmsRsaPssProvider.prototype, 'onExportKey'),
    (format: KeyFormat) => {
      expect(format).toBe('spki');
      return Promise.resolve(stubPublicKeySerialized);
    },
  );

  describe('RSA modulus', () => {
    test('Invalid modulus should be refused', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);
      const invalidModulus = 1024;

      await expect(
        provider.generateKey({ ...ALGORITHM, modulusLength: invalidModulus }, true, KEY_USAGES),
      ).rejects.toThrowWithMessage(KmsError, `Unsupported RSA modulus (${invalidModulus})`);
    });

    test.each([2048, 3072, 4096])('RSA modulus %s should be supported', async (modulusLength) => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      await provider.generateKey({ ...ALGORITHM, modulusLength }, true, KEY_USAGES);

      const expectedAlgorithm = `RSA_SIGN_PSS_${modulusLength}_SHA256`;
      expect(kmsClient.createCryptoKey).toHaveBeenCalledWith(
        expect.toSatisfy(
          (req: any) => req.cryptoKey.versionTemplate.algorithm === expectedAlgorithm,
        ),
        expect.anything(),
      );
    });
  });

  describe('Hash', () => {
    test('Invalid hashing algorithm should be refused', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);
      const invalidHashingAlgorithm = 'SHA-384';

      await expect(
        provider.generateKey(
          { ...ALGORITHM, hash: { name: invalidHashingAlgorithm } },
          true,
          KEY_USAGES,
        ),
      ).rejects.toThrowWithMessage(
        Error,
        /Must be one of/, // Comes from webcrypto-core
      );
    });

    test.each([256, 512])('SHA-%s should be supported', async (shaBitLength) => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);
      const hash = { name: `SHA-${shaBitLength}` };

      await provider.generateKey({ ...ALGORITHM, hash }, true, KEY_USAGES);

      const expectedAlgorithm = `RSA_SIGN_PSS_2048_SHA${shaBitLength}`;
      expect(kmsClient.createCryptoKey).toHaveBeenCalledWith(
        expect.toSatisfy(
          (req: any) => req.cryptoKey.versionTemplate.algorithm === expectedAlgorithm,
        ),
        expect.anything(),
      );
    });
  });

  test('Key purpose should be ASYMMETRIC_SIGN', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.generateKey(ALGORITHM, true, KEY_USAGES);

    expect(kmsClient.createCryptoKey).toHaveBeenCalledWith(
      expect.toSatisfy((req: any) => req.cryptoKey.purpose === 'ASYMMETRIC_SIGN'),
      expect.anything(),
    );
  });

  test('Key should be created under specified key ring', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.generateKey(ALGORITHM, true, KEY_USAGES);

    const keyRingName = kmsClient.keyRingPath(GCP_PROJECT, KMS_CONFIG.location, KMS_CONFIG.keyRing);
    expect(kmsClient.createCryptoKey).toHaveBeenCalledWith(
      expect.objectContaining({ parent: keyRingName }),
      expect.anything(),
    );
  });

  test('Key name should be a UUID', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.generateKey(ALGORITHM, true, KEY_USAGES);

    expect(kmsClient.createCryptoKey).toHaveBeenCalledWith(
      expect.objectContaining({ cryptoKeyId: mockStubUuid4 }),
      expect.anything(),
    );
  });

  test('Key should be created with an initial version', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.generateKey(ALGORITHM, true, KEY_USAGES);

    expect(kmsClient.createCryptoKey).toHaveBeenCalledWith(
      expect.objectContaining({ skipInitialVersionCreation: false }),
      expect.anything(),
    );
  });

  test.each<ProtectionLevel>(['SOFTWARE', 'HSM'])(
    'Protection level %s should be supported',
    async (protectionLevel: ProtectionLevel) => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, { ...KMS_CONFIG, protectionLevel });

      await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      expect(kmsClient.createCryptoKey).toHaveBeenCalledWith(
        expect.toSatisfy(
          (req: any) => req.cryptoKey.versionTemplate.protectionLevel === protectionLevel,
        ),
        expect.anything(),
      );
    },
  );

  describe('Destruction schedule', () => {
    test('Destruction schedule should default to 1 day', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      const oneDayInSeconds = 86_400;
      expect(kmsClient.createCryptoKey).toHaveBeenCalledWith(
        expect.toSatisfy(
          (req: any) => req.cryptoKey.destroyScheduledDuration.seconds === oneDayInSeconds,
        ),
        expect.anything(),
      );
    });

    test('Destruction schedule should be honoured if set', async () => {
      const kmsClient = makeKmsClient();
      const destroyScheduledDurationSeconds = 42;
      const provider = new GcpKmsRsaPssProvider(kmsClient, {
        ...KMS_CONFIG,
        destroyScheduledDurationSeconds,
      });

      await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      expect(kmsClient.createCryptoKey).toHaveBeenCalledWith(
        expect.toSatisfy(
          (req: any) =>
            req.cryptoKey.destroyScheduledDuration.seconds === destroyScheduledDurationSeconds,
        ),
        expect.anything(),
      );
    });
  });

  describe('Error handling', () => {
    test('Creation call should time out after 3 seconds', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      expect(kmsClient.createCryptoKey).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ timeout: 3_000 }),
      );
    });

    test('Creation call should be retried', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      expect(kmsClient.createCryptoKey).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ maxRetries: 10 }),
      );
    });

    test('Error to create key version should be wrapped', async () => {
      const callError = new Error('Cannot create key version');
      const kmsClient = makeKmsClient();
      jest.spyOn(kmsClient, 'createCryptoKey').mockImplementation(async () => {
        throw callError;
      });
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      const error = await catchPromiseRejection(
        provider.generateKey(ALGORITHM, true, KEY_USAGES),
        KmsError,
      );

      expect(error.message).toStartWith('Failed to create key');
      expect(error.cause).toEqual(callError);
    });
  });

  describe('Private key', () => {
    test('Key version should be populated correctly', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      const { privateKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      const kmsKeyVersionPath = kmsClient.cryptoKeyVersionPath(
        GCP_PROJECT,
        KMS_CONFIG.location,
        KMS_CONFIG.keyRing,
        mockStubUuid4,
        '1',
      );
      expect(privateKey).toHaveProperty('kmsKeyVersionPath', kmsKeyVersionPath);
    });

    test('Algorithm should be populated correctly', async () => {
      const provider = new GcpKmsRsaPssProvider(makeKmsClient(), KMS_CONFIG);

      const { privateKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      expect(privateKey.algorithm).toHaveProperty('hash', HASHING_ALGORITHM);
    });

    test('Existing provider should be included', async () => {
      const provider = new GcpKmsRsaPssProvider(makeKmsClient(), KMS_CONFIG);

      const { privateKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      expect(privateKey).toBeInstanceOf(GcpKmsRsaPssPrivateKey);
      expect((privateKey as GcpKmsRsaPssPrivateKey).provider).toBe(provider);
    });
  });

  describe('Public key', () => {
    test('Public key should match private key', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      const { privateKey, publicKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      expect(mockOnExportKey).toHaveBeenCalledWith('spki', privateKey);
      await expect(derSerializePublicKey(publicKey)).resolves.toEqual(
        Buffer.from(stubPublicKeySerialized),
      );
    });

    test('Key algorithm should be populated correctly', async () => {
      const provider = new GcpKmsRsaPssProvider(makeKmsClient(), KMS_CONFIG);

      const { publicKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      expect(publicKey.algorithm).toEqual(ALGORITHM);
    });

    test('Key should be extractable', async () => {
      const provider = new GcpKmsRsaPssProvider(makeKmsClient(), KMS_CONFIG);

      const { publicKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      expect(publicKey.extractable).toBe(true);
    });

    test('Key usages should only include "verify"', async () => {
      const provider = new GcpKmsRsaPssProvider(makeKmsClient(), KMS_CONFIG);

      const { publicKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      expect(publicKey.usages).toEqual(['verify']);
    });
  });

  function makeKmsClient(): KeyManagementServiceClient {
    const kmsClient = new KeyManagementServiceClient();

    jest.spyOn(kmsClient, 'createCryptoKey').mockImplementation(({ cryptoKeyId }) => [
      {
        name: kmsClient.cryptoKeyPath(
          GCP_PROJECT,
          KMS_CONFIG.location,
          KMS_CONFIG.keyRing,
          cryptoKeyId as string,
        ),
      },
      undefined,
      undefined,
    ]);

    jest.spyOn(kmsClient, 'getProjectId').mockImplementation(() => GCP_PROJECT);

    jest.spyOn<KeyManagementServiceClient, any>(kmsClient, 'getPublicKey').mockResolvedValue([
      {
        pem: REAL_PUBLIC_KEY.toString('base64'),
      },
    ]);

    return kmsClient;
  }
});

describe('onExportKey', () => {
  test.each(['jwt', 'pkcs8'] as readonly KeyFormat[])(
    '%s export should be unsupported',
    async (format) => {
      const provider = new GcpKmsRsaPssProvider(null as any, KMS_CONFIG);

      await expect(provider.onExportKey(format, PRIVATE_KEY)).rejects.toThrowWithMessage(
        KmsError,
        'Private key cannot be exported',
      );
    },
  );

  describe('Raw', () => {
    test('KMS key version path should be output', async () => {
      const provider = new GcpKmsRsaPssProvider(null as any, KMS_CONFIG);

      const rawKey = (await provider.exportKey('raw', PRIVATE_KEY)) as ArrayBuffer;

      expect(Buffer.from(rawKey).toString()).toEqual(PRIVATE_KEY.kmsKeyVersionPath);
    });
  });

  describe('SPKI', () => {
    test('Specified key version name should be retrieved', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      await provider.exportKey('spki', PRIVATE_KEY);

      expect(kmsClient.getPublicKey).toHaveBeenCalledWith(
        expect.objectContaining({ name: PRIVATE_KEY.kmsKeyVersionPath }),
        expect.anything(),
      );
    });

    test('Public key should be output DER-serialised', async () => {
      const publicKeyDer = Buffer.from('This is a DER-encoded public key :wink:');
      const kmsClient = makeKmsClient(derPublicKeyToPem(publicKeyDer));
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      const publicKey = await provider.exportKey('spki', PRIVATE_KEY);

      expect(publicKey).toBeInstanceOf(ArrayBuffer);
      expect(Buffer.from(publicKey as ArrayBuffer)).toEqual(publicKeyDer);
    });

    test('Public key export should time out after 300ms', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      await provider.exportKey('spki', PRIVATE_KEY);

      expect(kmsClient.getPublicKey).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ timeout: 300 }),
      );
    });

    test('Public key export should be retried up to 3 times', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      await provider.exportKey('spki', PRIVATE_KEY);

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
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      const publicKey = await provider.exportKey('spki', PRIVATE_KEY);

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
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      await catchPromiseRejection(provider.exportKey('spki', PRIVATE_KEY), KmsError);

      expect(kmsClient.getPublicKey).toHaveBeenCalledTimes(1);
    });

    test('Any other errors should be wrapped', async () => {
      const callError = new Error('The service is down');
      const kmsClient = makeKmsClient(callError);
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      const error = await catchPromiseRejection(provider.exportKey('spki', PRIVATE_KEY), KmsError);

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
    const provider = new GcpKmsRsaPssProvider(null as any, KMS_CONFIG);
    const invalidKey = new CryptoKey();

    await expect(provider.onExportKey('spki', invalidKey)).rejects.toThrowWithMessage(
      KmsError,
      'Key is not managed by GCP KMS',
    );
  });
});

describe('onImportKey', () => {
  const ALGORITHM = RSA_PSS_IMPORT_ALGORITHM;
  const KEY_DATA = bufferToArrayBuffer(Buffer.from(KMS_KEY_VERSION_PATH));

  test.each(['jwk', 'pkcs8', 'spki'] as readonly KeyFormat[])(
    'Format %s should be unsupported',
    async (format) => {
      const provider = new GcpKmsRsaPssProvider(null as any, KMS_CONFIG);

      await expect(provider.onImportKey(format, KEY_DATA, ALGORITHM)).rejects.toThrowWithMessage(
        KmsError,
        'Private key can only be exported to raw format',
      );
    },
  );

  describe('Raw', () => {
    test('KMS key version path should be extracted', async () => {
      const provider = new GcpKmsRsaPssProvider(null as any, KMS_CONFIG);

      const privateKey = await provider.importKey('raw', KEY_DATA, ALGORITHM, true, KEY_USAGES);

      expect(privateKey).toBeInstanceOf(GcpKmsRsaPssPrivateKey);
      expect((privateKey as GcpKmsRsaPssPrivateKey).kmsKeyVersionPath).toEqual(
        KMS_KEY_VERSION_PATH,
      );
    });

    test('Hashing algorithm should be honoured', async () => {
      const provider = new GcpKmsRsaPssProvider(null as any, KMS_CONFIG);

      const privateKey = await provider.importKey('raw', KEY_DATA, ALGORITHM, true, KEY_USAGES);

      expect(privateKey.algorithm).toStrictEqual(ALGORITHM);
    });

    test('Provider instance should be attached to key', async () => {
      const provider = new GcpKmsRsaPssProvider(null as any, KMS_CONFIG);

      const privateKey = await provider.importKey('raw', KEY_DATA, ALGORITHM, true, KEY_USAGES);

      expect((privateKey as GcpKmsRsaPssPrivateKey).provider).toBe(provider);
    });
  });
});

describe('onSign', () => {
  const ALGORITHM = RSA_PSS_SIGN_ALGORITHM;

  test('Non-KMS key should be refused', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);
    const invalidKey = CryptoKey.create({ name: 'RSA-PSS' }, 'private', true, ['sign']);

    await expect(provider.sign(ALGORITHM, invalidKey, PLAINTEXT)).rejects.toThrowWithMessage(
      KmsError,
      `Cannot sign with key of unsupported type (${invalidKey.constructor.name})`,
    );

    expect(kmsClient.asymmetricSign).not.toHaveBeenCalled();
  });

  test('Signature should be output', async () => {
    const kmsClient = makeKmsClient({ signature: SIGNATURE });
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    const signature = await provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT);

    expect(Buffer.from(signature)).toEqual(SIGNATURE);
  });

  test('Correct key path should be used', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.objectContaining({ name: PRIVATE_KEY.kmsKeyVersionPath }),
      expect.anything(),
    );
  });

  test('Correct plaintext should be passed', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.toSatisfy((req) => Buffer.from(req.data).equals(Buffer.from(PLAINTEXT))),
      expect.anything(),
    );
  });

  test('Plaintext CRC32C checksum should be passed to KMS', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.objectContaining({ dataCrc32c: { value: calculateCRC32C(Buffer.from(PLAINTEXT)) } }),
      expect.anything(),
    );
  });

  test('KMS should verify signature CRC32C checksum from the client', async () => {
    const provider = new GcpKmsRsaPssProvider(
      makeKmsClient({ verifiedSignatureCRC32C: false }),
      KMS_CONFIG,
    );

    await expect(provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT)).rejects.toThrowWithMessage(
      KmsError,
      'KMS failed to verify plaintext CRC32C checksum',
    );
  });

  test('Signature CRC32C checksum from the KMS should be verified', async () => {
    const provider = new GcpKmsRsaPssProvider(
      makeKmsClient({ signatureCRC32C: calculateCRC32C(SIGNATURE) - 1 }),
      KMS_CONFIG,
    );

    await expect(provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT)).rejects.toThrowWithMessage(
      KmsError,
      'Signature CRC32C checksum does not match one received from KMS',
    );
  });

  test('KMS should sign with the specified key', async () => {
    const kmsKeyVersionName = `not-${PRIVATE_KEY.kmsKeyVersionPath}`;
    const provider = new GcpKmsRsaPssProvider(makeKmsClient({ kmsKeyVersionName }), KMS_CONFIG);

    await expect(provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT)).rejects.toThrowWithMessage(
      KmsError,
      `KMS used the wrong key version (${kmsKeyVersionName})`,
    );
  });

  test('Request should time out after 3 seconds', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ timeout: 3_000 }),
    );
  });

  test('Request should be retried', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ maxRetries: 10 }),
    );
  });

  test('API call errors should be wrapped', async () => {
    const callError = new Error('Bruno. There. I said it.');
    const provider = new GcpKmsRsaPssProvider(makeKmsClient(callError), KMS_CONFIG);

    const error = await catchPromiseRejection(
      provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT),
      KmsError,
    );

    expect(error.message).toStartWith('KMS signature request failed');
    expect(error.cause).toEqual(callError);
  });

  describe('Algorithm parameters', () => {
    test.each([32, 64])('Salt length of %s should be accepted', async (saltLength) => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);
      const algorithm = { ...ALGORITHM, saltLength };

      await provider.sign(algorithm, PRIVATE_KEY, PLAINTEXT);
    });

    test.each([20, 48])('Salt length of %s should be refused', async (saltLength) => {
      // 20 and 48 are used by SHA-1 and SHA-384, respectively, which are unsupported
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);
      const algorithm = { ...ALGORITHM, saltLength };

      await expect(provider.sign(algorithm, PRIVATE_KEY, PLAINTEXT)).rejects.toThrowWithMessage(
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
        name: responseOrError.kmsKeyVersionName ?? PRIVATE_KEY.kmsKeyVersionPath,
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
    const provider = new GcpKmsRsaPssProvider(null as any, KMS_CONFIG);

    await expect(provider.onVerify()).rejects.toThrowWithMessage(
      KmsError,
      'Signature verification is unsupported',
    );
  });
});

describe('close', () => {
  test('Client should be closed', async () => {
    const client = new KeyManagementServiceClient();
    const mockClose = jest.spyOn(client, 'close').mockResolvedValue(undefined);
    const provider = new GcpKmsRsaPssProvider(client, KMS_CONFIG);

    await provider.close();

    expect(mockClose).toHaveBeenCalledWith();
  });
});
