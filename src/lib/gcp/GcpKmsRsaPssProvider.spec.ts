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
import { derSerializePublicKey } from '../../testUtils/crypto';

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

let stubPrivateKey: GcpKmsRsaPssPrivateKey;
const HASHING_ALGORITHM_NAME = 'SHA-256';
beforeAll(async () => {
  stubPrivateKey = new GcpKmsRsaPssPrivateKey(
    '/the/path/key-name',
    HASHING_ALGORITHM_NAME,
    new GcpKmsRsaPssProvider(null as any, KMS_CONFIG),
  );
});

describe('hashingAlgorithms', () => {
  test('Only SHA-256 and SHA-512 should be supported', async () => {
    const provider = new GcpKmsRsaPssProvider(null as any, KMS_CONFIG);

    expect(provider.hashAlgorithms).toEqual([HASHING_ALGORITHM_NAME, 'SHA-512']);
  });
});

describe('onGenerateKey', () => {
  /**
   * Actual public key exported from GCP KMS.
   *
   * Copied here to avoid interoperability issues -- namely around the serialisation of
   * `AlgorithmParams` (`NULL` vs absent).
   */
  const STUB_KMS_PUBLIC_KEY = Buffer.from(
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnL8hQlf3GLajYh5NA6k7bpHPYUxjiZJgOEiDs8y1iPa6p' +
      '/40p6OeFAakIgqNBZS4CfWnZQ8fPJxCN3ctRMOXQqyajkXHqcUO07shjlvJA9niPQfqpLF2izdSimqMdZkPDfOs4Q' +
      '254+ZLld/JpGn4CocYMaACXWrT+sY4CWw0EJh2kWKcEWF9Z5TL7wA+mJyHZN/cTndIM1kORb8ADzNfyBPMhGRp31N' +
      '4dLff0H28MQCr/0GPbAA+5dMReCPTMLollAI4JmaNtYEaw32sSsH35POtfVz91ui5AaxVONapfw4NfLrxdBvySBhZ' +
      'Zq76INzyG6uwx7TDqJwy0e+SLmF4mQIDAQAB',
    'base64',
  );

  const HASHING_ALGORITHM = { name: HASHING_ALGORITHM_NAME };
  const ALGORITHM: RsaHashedKeyGenParams = {
    name: 'RSA-PSS',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: HASHING_ALGORITHM,
  };
  // tslint:disable-next-line:readonly-array
  const KEY_USAGES: KeyUsage[] = ['sign'];

  let stubPublicKeySerialized: ArrayBuffer;
  beforeAll(async () => {
    stubPublicKeySerialized = bufferToArrayBuffer(STUB_KMS_PUBLIC_KEY);
  });

  const mockOnExportKey = mockSpy(
    jest.spyOn(GcpKmsRsaPssProvider.prototype, 'onExportKey'),
    (format: KeyFormat) => {
      expect(format).toBe('spki');
      return Promise.resolve(stubPublicKeySerialized);
    },
  );

  describe('Key validation', () => {
    test('Key should use be a signing key with RSA-PSS algorithm', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);
      const invalidAlgorithmName = 'RSA-OAEP';

      await expect(
        provider.generateKey({ ...ALGORITHM, name: invalidAlgorithmName }, true, KEY_USAGES),
      ).rejects.toThrow(
        Error, // Comes from webcrypto-core
      );
    });

    test('Invalid modulus should be refused', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);
      const invalidModulus = 1024;

      await expect(
        provider.generateKey({ ...ALGORITHM, modulusLength: invalidModulus }, true, KEY_USAGES),
      ).rejects.toThrowWithMessage(KmsError, `Unsupported RSA modulus (${invalidModulus})`);
    });

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
  });

  describe('KMS key creation', () => {
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

      const keyRingName = kmsClient.keyRingPath(
        GCP_PROJECT,
        KMS_CONFIG.location,
        KMS_CONFIG.keyRing,
      );
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

    test('Creation call should time out after 3 seconds', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      expect(kmsClient.createCryptoKey).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ timeout: 3_000 }),
      );
    });

    test('Version creation call should be retried', async () => {
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
        pem: STUB_KMS_PUBLIC_KEY.toString('base64'),
      },
    ]);

    return kmsClient;
  }
});

describe('onImportKey', () => {
  test('Method should not be supported', async () => {
    const provider = new GcpKmsRsaPssProvider(null as any, KMS_CONFIG);

    await expect(provider.onImportKey()).rejects.toThrowWithMessage(
      KmsError,
      'Key import is unsupported',
    );
  });
});

describe('onSign', () => {
  const PLAINTEXT = bufferToArrayBuffer(Buffer.from('the plaintext'));
  const SIGNATURE = Buffer.from('the signature');
  const ALGORITHM_PARAMS: RsaPssParams = { name: 'RSA-PSS', saltLength: 32 };

  test('Non-KMS key should be refused', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);
    const invalidKey = CryptoKey.create({ name: 'RSA-PSS' }, 'private', true, ['sign']);

    await expect(provider.sign(ALGORITHM_PARAMS, invalidKey, PLAINTEXT)).rejects.toThrowWithMessage(
      KmsError,
      `Cannot sign with key of unsupported type (${invalidKey.constructor.name})`,
    );

    expect(kmsClient.asymmetricSign).not.toHaveBeenCalled();
  });

  test('Signature should be output', async () => {
    const kmsClient = makeKmsClient({ signature: SIGNATURE });
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    const signature = await provider.sign(ALGORITHM_PARAMS, stubPrivateKey, PLAINTEXT);

    expect(Buffer.from(signature)).toEqual(SIGNATURE);
  });

  test('Correct key path should be used', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.sign(ALGORITHM_PARAMS, stubPrivateKey, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.objectContaining({ name: stubPrivateKey.kmsKeyVersionPath }),
      expect.anything(),
    );
  });

  test('Correct plaintext should be passed', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.sign(ALGORITHM_PARAMS, stubPrivateKey, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.toSatisfy((req) => Buffer.from(req.data).equals(Buffer.from(PLAINTEXT))),
      expect.anything(),
    );
  });

  test('Plaintext CRC32C checksum should be passed to KMS', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.sign(ALGORITHM_PARAMS, stubPrivateKey, PLAINTEXT);

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

    await expect(
      provider.sign(ALGORITHM_PARAMS, stubPrivateKey, PLAINTEXT),
    ).rejects.toThrowWithMessage(KmsError, 'KMS failed to verify plaintext CRC32C checksum');
  });

  test('Signature CRC32C checksum from the KMS should be verified', async () => {
    const provider = new GcpKmsRsaPssProvider(
      makeKmsClient({ signatureCRC32C: calculateCRC32C(SIGNATURE) - 1 }),
      KMS_CONFIG,
    );

    await expect(
      provider.sign(ALGORITHM_PARAMS, stubPrivateKey, PLAINTEXT),
    ).rejects.toThrowWithMessage(
      KmsError,
      'Signature CRC32C checksum does not match one received from KMS',
    );
  });

  test('KMS should sign with the specified key', async () => {
    const kmsKeyVersionName = `not-${stubPrivateKey.kmsKeyVersionPath}`;
    const provider = new GcpKmsRsaPssProvider(makeKmsClient({ kmsKeyVersionName }), KMS_CONFIG);

    await expect(
      provider.sign(ALGORITHM_PARAMS, stubPrivateKey, PLAINTEXT),
    ).rejects.toThrowWithMessage(KmsError, `KMS used the wrong key version (${kmsKeyVersionName})`);
  });

  test('Request should time out after 3 seconds', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.sign(ALGORITHM_PARAMS, stubPrivateKey, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ timeout: 3_000 }),
    );
  });

  test('Request should be retried', async () => {
    const kmsClient = makeKmsClient();
    const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

    await provider.sign(ALGORITHM_PARAMS, stubPrivateKey, PLAINTEXT);

    expect(kmsClient.asymmetricSign).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ maxRetries: 10 }),
    );
  });

  test('API call errors should be wrapped', async () => {
    const callError = new Error('Bruno. There. I said it.');
    const provider = new GcpKmsRsaPssProvider(makeKmsClient(callError), KMS_CONFIG);

    const error = await catchPromiseRejection(
      provider.sign(ALGORITHM_PARAMS, stubPrivateKey, PLAINTEXT),
      KmsError,
    );

    expect(error.message).toStartWith('KMS signature request failed');
    expect(error.cause).toEqual(callError);
  });

  describe('Algorithm parameters', () => {
    test.each([32, 64])('Salt length of %s should be accepted', async (saltLength) => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);
      const algorithm = { ...ALGORITHM_PARAMS, saltLength };

      await provider.sign(algorithm, stubPrivateKey, PLAINTEXT);
    });

    test.each([20, 48])('Salt length of %s should be refused', async (saltLength) => {
      // 20 and 48 are used by SHA-1 and SHA-384, respectively, which are unsupported
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);
      const algorithm = { ...ALGORITHM_PARAMS, saltLength };

      await expect(provider.sign(algorithm, stubPrivateKey, PLAINTEXT)).rejects.toThrowWithMessage(
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
        name: responseOrError.kmsKeyVersionName ?? stubPrivateKey.kmsKeyVersionPath,
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

describe('onExportKey', () => {
  test.each(['jwt', 'pkcs8', 'raw'] as readonly KeyFormat[])(
    '%s export should be unsupported',
    async (format) => {
      const provider = new GcpKmsRsaPssProvider(null as any, KMS_CONFIG);

      await expect(provider.onExportKey(format, stubPrivateKey)).rejects.toThrowWithMessage(
        KmsError,
        'Private key cannot be exported',
      );
    },
  );

  // noinspection JSMismatchedCollectionQueryUpdate
  describe('SPKI', () => {
    test('Specified key version name should be honored', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      await provider.exportKey('spki', stubPrivateKey);

      expect(kmsClient.getPublicKey).toHaveBeenCalledWith(
        expect.objectContaining({ name: stubPrivateKey.kmsKeyVersionPath }),
        expect.anything(),
      );
    });

    test('Public key should be output DER-serialized', async () => {
      const publicKeyDer = Buffer.from('This is a DER-encoded public key :wink:');
      const kmsClient = makeKmsClient(derPublicKeyToPem(publicKeyDer));
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      const publicKey = await provider.exportKey('spki', stubPrivateKey);

      expect(publicKey).toBeInstanceOf(ArrayBuffer);
      expect(Buffer.from(publicKey as ArrayBuffer)).toEqual(publicKeyDer);
    });

    test('Public key export should time out after 300ms', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      await provider.exportKey('spki', stubPrivateKey);

      expect(kmsClient.getPublicKey).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ timeout: 300 }),
      );
    });

    test('Public key export should be retried up to 3 times', async () => {
      const kmsClient = makeKmsClient();
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      await provider.exportKey('spki', stubPrivateKey);

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

      const publicKey = await provider.exportKey('spki', stubPrivateKey);

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

      await catchPromiseRejection(provider.exportKey('spki', stubPrivateKey), KmsError);

      expect(kmsClient.getPublicKey).toHaveBeenCalledTimes(1);
    });

    test('Any other errors should be wrapped', async () => {
      const callError = new Error('The service is down');
      const kmsClient = makeKmsClient(callError);
      const provider = new GcpKmsRsaPssProvider(kmsClient, KMS_CONFIG);

      const error = await catchPromiseRejection(
        provider.exportKey('spki', stubPrivateKey),
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
      'Key is not managed by KMS',
    );
  });
});
