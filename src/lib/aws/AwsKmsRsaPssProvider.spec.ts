import {
  CreateKeyCommand,
  CreateKeyCommandOutput,
  GetPublicKeyCommand,
  GetPublicKeyCommandOutput,
  KeyUsageType,
  KMSClient,
  SignCommand,
  SignCommandOutput,
} from '@aws-sdk/client-kms';
import { CryptoKey } from 'webcrypto-core';

import { AwsKmsRsaPssProvider } from './AwsKmsRsaPssProvider';
import {
  derSerializePublicKey,
  HASHING_ALGORITHM,
  HASHING_ALGORITHM_NAME,
  KEY_USAGES,
  NODEJS_CRYPTO,
  RSA_PSS_CREATION_ALGORITHM,
  RSA_PSS_IMPORT_ALGORITHM,
  RSA_PSS_SIGN_ALGORITHM,
} from '../../testUtils/webcrypto';
import { KmsError } from '../KmsError';
import { AwsKmsRsaPssPrivateKey } from './AwsKmsRsaPssPrivateKey';
import { getMockInstance } from '../../testUtils/jest';
import { PLAINTEXT, REAL_PUBLIC_KEYS, SIGNATURE } from '../../testUtils/stubs';
import { bufferToArrayBuffer } from '../utils/buffer';
import { HashingAlgorithm } from '../algorithms';

const AWS_KMS_KEY_ID = '24c7110a-af17-43d9-86ab-17294034c3d8';
const AWS_KMS_KEY_ARN = `arn:aws:kms:eu-west-2:111122223333:key/${AWS_KMS_KEY_ID}`;

const PRIVATE_KEY = new AwsKmsRsaPssPrivateKey(
  AWS_KMS_KEY_ARN,
  HASHING_ALGORITHM_NAME,
  null as any,
);

const REAL_PUBLIC_KEY = REAL_PUBLIC_KEYS.aws;

describe('AwsKmsRsaPssProvider', () => {
  describe('onGenerate', () => {
    const ALGORITHM = RSA_PSS_CREATION_ALGORITHM;

    test('Key creation command should be used', async () => {
      const client = makeAwsClient();
      const provider = new AwsKmsRsaPssProvider(client);

      await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      expect(client.send).toHaveBeenCalledWith(expect.any(CreateKeyCommand), expect.anything());
    });

    describe('RSA modulus', () => {
      test('Invalid modulus should be refused', async () => {
        const provider = new AwsKmsRsaPssProvider(makeAwsClient());
        const invalidModulus = 1024;

        await expect(
          provider.generateKey({ ...ALGORITHM, modulusLength: invalidModulus }, true, KEY_USAGES),
        ).rejects.toThrowWithMessage(KmsError, `Unsupported RSA modulus (${invalidModulus})`);
      });

      test.each([2048, 3072, 4096])('RSA modulus %s should be supported', async (modulusLength) => {
        const client = makeAwsClient();
        const provider = new AwsKmsRsaPssProvider(client);

        await provider.generateKey({ ...ALGORITHM, modulusLength }, true, KEY_USAGES);

        const expectedAlgorithm = `RSA_${modulusLength}`;
        expect(client.send).toHaveBeenCalledWith(
          expect.objectContaining<Partial<CreateKeyCommand>>({
            input: expect.objectContaining({ KeySpec: expectedAlgorithm }),
          }),
          expect.anything(),
        );
      });
    });

    test('Key usage should be SIGN_VERIFY', async () => {
      const client = makeAwsClient();
      const provider = new AwsKmsRsaPssProvider(client);

      await provider.generateKey(ALGORITHM, true, KEY_USAGES);

      expect(client.send).toHaveBeenCalledWith(
        expect.objectContaining<Partial<CreateKeyCommand>>({
          input: expect.objectContaining({ KeyUsage: KeyUsageType.SIGN_VERIFY }),
        }),
        expect.anything(),
      );
    });

    describe('Error handling', () => {
      test('Response with missing KeyMetadata should be refused', async () => {
        const client = makeAwsClient();
        const response: CreateKeyCommandOutput = { $metadata: {} };
        getMockInstance(client.send).mockResolvedValue(response);
        const provider = new AwsKmsRsaPssProvider(client);

        await expect(provider.generateKey(ALGORITHM, true, KEY_USAGES)).rejects.toThrowWithMessage(
          KmsError,
          'Key creation response is missing KeyMetadata.Arn',
        );
      });

      test('Response with missing ARN should be refused', async () => {
        const client = makeAwsClient();
        const response: CreateKeyCommandOutput = {
          $metadata: {},
          KeyMetadata: { KeyId: AWS_KMS_KEY_ID },
        };
        getMockInstance(client.send).mockResolvedValue(response);
        const provider = new AwsKmsRsaPssProvider(client);

        await expect(provider.generateKey(ALGORITHM, true, KEY_USAGES)).rejects.toThrowWithMessage(
          KmsError,
          'Key creation response is missing KeyMetadata.Arn',
        );
      });

      test('Call should time out after 3 seconds', async () => {
        const client = makeAwsClient();
        const provider = new AwsKmsRsaPssProvider(client);

        await provider.generateKey(ALGORITHM, true, KEY_USAGES);

        expect(client.send).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ requestTimeout: 3_000 }),
        );
      });
    });

    describe('Private key', () => {
      test('Key ARN should be populated correctly', async () => {
        const provider = new AwsKmsRsaPssProvider(makeAwsClient());

        const { privateKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

        expect(privateKey).toBeInstanceOf(AwsKmsRsaPssPrivateKey);
        expect((privateKey as AwsKmsRsaPssPrivateKey).arn).toBe(AWS_KMS_KEY_ARN);
      });

      test('Algorithm should be populated correctly', async () => {
        const provider = new AwsKmsRsaPssProvider(makeAwsClient());

        const { privateKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

        expect(privateKey.algorithm).toHaveProperty('hash', HASHING_ALGORITHM);
      });

      test('Existing provider should be included', async () => {
        const provider = new AwsKmsRsaPssProvider(makeAwsClient());

        const { privateKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

        expect((privateKey as AwsKmsRsaPssPrivateKey).provider).toBe(provider);
      });
    });

    describe('Public key', () => {
      test('Public key should match private key', async () => {
        const client = makeAwsClient();
        const provider = new AwsKmsRsaPssProvider(client);

        const { privateKey, publicKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

        expect(client.send).toHaveBeenCalledWith(
          expect.toSatisfy(
            (command: any) =>
              command instanceof GetPublicKeyCommand &&
              command.input.KeyId === (privateKey as AwsKmsRsaPssPrivateKey).arn,
          ),
          expect.anything(),
        );
        await expect(derSerializePublicKey(publicKey)).resolves.toEqual(
          Buffer.from(REAL_PUBLIC_KEY),
        );
      });

      test('Key algorithm should be populated correctly', async () => {
        const provider = new AwsKmsRsaPssProvider(makeAwsClient());

        const { publicKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

        expect(publicKey.algorithm).toStrictEqual(ALGORITHM);
      });

      test('Key should be extractable', async () => {
        const provider = new AwsKmsRsaPssProvider(makeAwsClient());

        const { publicKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

        expect(publicKey.extractable).toBeTrue();
      });

      test('Key usages should only include "verify"', async () => {
        const provider = new AwsKmsRsaPssProvider(makeAwsClient());

        const { publicKey } = await provider.generateKey(ALGORITHM, true, KEY_USAGES);

        expect(publicKey.usages).toStrictEqual(['verify']);
      });
    });

    function makeAwsClient(): KMSClient {
      const client = new KMSClient({});
      const createKeyCommandOutput: CreateKeyCommandOutput = {
        $metadata: {},
        KeyMetadata: {
          Arn: AWS_KMS_KEY_ARN,
          KeyId: AWS_KMS_KEY_ID,
        },
      };
      const getPublicKeyCommandOutput: GetPublicKeyCommandOutput = {
        $metadata: {},
        PublicKey: new Uint8Array(REAL_PUBLIC_KEY),
      };
      jest.spyOn<KMSClient, any>(client, 'send').mockImplementation(async (command) => {
        if (command instanceof CreateKeyCommand) {
          return createKeyCommandOutput;
        } else if (command instanceof GetPublicKeyCommand) {
          return getPublicKeyCommandOutput;
        } else {
          throw new Error('Unsupported command');
        }
      });
      return client;
    }
  });

  describe('hashingAlgorithms', () => {
    test('Only SHA-256, SHA-384 and SHA-512 should be supported', async () => {
      const provider = new AwsKmsRsaPssProvider(null as any);

      expect(provider.hashAlgorithms).toEqual(['SHA-256', 'SHA-384', 'SHA-512']);
    });
  });

  describe('onExport', () => {
    test.each(['jwt', 'pkcs8'] as readonly KeyFormat[])(
      '%s export should be unsupported',
      async (format) => {
        const provider = new AwsKmsRsaPssProvider(makeAwsClient());

        await expect(provider.onExportKey(format, PRIVATE_KEY)).rejects.toThrowWithMessage(
          KmsError,
          'Private key cannot be exported',
        );
      },
    );

    describe('Raw', () => {
      test('Key ARN should be output', async () => {
        const provider = new AwsKmsRsaPssProvider(makeAwsClient());

        const rawKey = (await provider.exportKey('raw', PRIVATE_KEY)) as ArrayBuffer;

        expect(Buffer.from(rawKey).toString()).toEqual(PRIVATE_KEY.arn);
      });
    });

    describe('SPKI', () => {
      test('Specified key ARN should be retrieved', async () => {
        const client = makeAwsClient();
        const provider = new AwsKmsRsaPssProvider(client);

        await provider.exportKey('spki', PRIVATE_KEY);

        expect(client.send).toHaveBeenCalledWith(
          expect.any(GetPublicKeyCommand),
          expect.anything(),
        );
        expect(client.send).toHaveBeenCalledWith(
          expect.objectContaining({ input: expect.objectContaining({ KeyId: PRIVATE_KEY.arn }) }),
          expect.anything(),
        );
      });

      test('Public key should be output DER-serialised', async () => {
        const provider = new AwsKmsRsaPssProvider(makeAwsClient());

        const publicKey = await provider.exportKey('spki', PRIVATE_KEY);

        expect(publicKey).toBeInstanceOf(ArrayBuffer);
        expect((publicKey as ArrayBuffer).byteLength).toEqual(REAL_PUBLIC_KEY.byteLength);
        expect(Buffer.from(publicKey as ArrayBuffer)).toEqual(REAL_PUBLIC_KEY);
      });

      test('Public key export should time out after 3 seconds', async () => {
        const client = makeAwsClient();
        const provider = new AwsKmsRsaPssProvider(client);

        await provider.exportKey('spki', PRIVATE_KEY);

        expect(client.send).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({ requestTimeout: 3_000 }),
        );
      });
    });

    test('Non-KMS key should be refused', async () => {
      const provider = new AwsKmsRsaPssProvider(makeAwsClient());
      const invalidKey = new CryptoKey();

      await expect(provider.onExportKey('spki', invalidKey)).rejects.toThrowWithMessage(
        KmsError,
        'Key is not managed by AWS KMS',
      );
    });

    function makeAwsClient(): KMSClient {
      const client = new KMSClient({});
      const response: GetPublicKeyCommandOutput = {
        $metadata: {},
        PublicKey: new Uint8Array(REAL_PUBLIC_KEY),
      };
      jest.spyOn<KMSClient, any>(client, 'send').mockResolvedValue(response);
      return client;
    }
  });

  describe('onImport', () => {
    const ALGORITHM = RSA_PSS_IMPORT_ALGORITHM;
    const KEY_DATA = bufferToArrayBuffer(Buffer.from(AWS_KMS_KEY_ARN));

    test.each(['jwk', 'pkcs8', 'spki'] as readonly KeyFormat[])(
      'Format %s should be unsupported',
      async (format) => {
        const provider = new AwsKmsRsaPssProvider(null as any);

        await expect(provider.onImportKey(format, KEY_DATA, ALGORITHM)).rejects.toThrowWithMessage(
          KmsError,
          'Private key can only be exported to raw format',
        );
      },
    );

    describe('Raw', () => {
      test('Key ARN should be extracted', async () => {
        const provider = new AwsKmsRsaPssProvider(null as any);

        const privateKey = await provider.importKey('raw', KEY_DATA, ALGORITHM, true, KEY_USAGES);

        expect(privateKey).toBeInstanceOf(AwsKmsRsaPssPrivateKey);
        expect((privateKey as AwsKmsRsaPssPrivateKey).arn).toEqual(AWS_KMS_KEY_ARN);
      });

      test('Hashing algorithm should be honoured', async () => {
        const provider = new AwsKmsRsaPssProvider(null as any);

        const privateKey = await provider.importKey('raw', KEY_DATA, ALGORITHM, true, KEY_USAGES);

        expect(privateKey.algorithm).toStrictEqual(ALGORITHM);
      });

      test('Provider instance should be attached to key', async () => {
        const provider = new AwsKmsRsaPssProvider(null as any);

        const privateKey = await provider.importKey('raw', KEY_DATA, ALGORITHM, true, KEY_USAGES);

        expect((privateKey as AwsKmsRsaPssPrivateKey).provider).toBe(provider);
      });
    });
  });

  describe('onSign', () => {
    const ALGORITHM = RSA_PSS_SIGN_ALGORITHM;

    test('Plaintext should be signed with specified key', async () => {
      const client = makeAwsClient();
      const provider = new AwsKmsRsaPssProvider(client);

      await provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT);

      expect(client.send).toHaveBeenCalledWith(expect.any(SignCommand), expect.anything());
      expect(client.send).toHaveBeenCalledWith(
        expect.objectContaining({
          input: expect.objectContaining({ KeyId: PRIVATE_KEY.arn }),
        }),
        expect.anything(),
      );
    });

    test.each<HashingAlgorithm>(['SHA-256', 'SHA-384', 'SHA-512'])(
      '%s digest should be supported',
      async (hashAlgorithm) => {
        const client = makeAwsClient();
        const provider = new AwsKmsRsaPssProvider(client);
        const privateKey = new AwsKmsRsaPssPrivateKey(PRIVATE_KEY.arn, hashAlgorithm, provider);

        await provider.sign(ALGORITHM, privateKey, PLAINTEXT);

        const expectedDigest = await NODEJS_CRYPTO.subtle.digest(hashAlgorithm, PLAINTEXT);
        const expectedAlgorithm = hashAlgorithm.replace('-', '_');
        expect(client.send).toHaveBeenCalledWith(
          expect.objectContaining({
            input: expect.objectContaining({
              Message: Buffer.from(expectedDigest),
              MessageType: 'DIGEST',
              SigningAlgorithm: `RSASSA_PSS_${expectedAlgorithm}`,
            }),
          }),
          expect.anything(),
        );
      },
    );

    test('Signature should be output', async () => {
      const provider = new AwsKmsRsaPssProvider(makeAwsClient());

      const signature = (await provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT)) as ArrayBuffer;

      expect(Buffer.from(signature)).toEqual(SIGNATURE);
    });

    test('Non-AWS KMS key should be refused', async () => {
      const provider = new AwsKmsRsaPssProvider(makeAwsClient());
      const invalidKey = new CryptoKey();

      await expect(provider.onSign(ALGORITHM, invalidKey, PLAINTEXT)).rejects.toThrowWithMessage(
        KmsError,
        'Key is not managed by AWS KMS',
      );
    });

    test('Call should time out after 3 seconds', async () => {
      const client = makeAwsClient();
      const provider = new AwsKmsRsaPssProvider(client);

      await provider.sign(ALGORITHM, PRIVATE_KEY, PLAINTEXT);

      expect(client.send).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ requestTimeout: 3_000 }),
      );
    });

    function makeAwsClient(): KMSClient {
      const client = new KMSClient({});
      const response: SignCommandOutput = {
        $metadata: {},
        Signature: new Uint8Array(SIGNATURE),
      };
      jest.spyOn<KMSClient, any>(client, 'send').mockResolvedValue(response);
      return client;
    }
  });

  describe('onVerify', () => {
    test('Verification should be unsupported', async () => {
      const provider = new AwsKmsRsaPssProvider(null as any);

      await expect(provider.onVerify()).rejects.toThrowWithMessage(
        KmsError,
        'Signature verification is unsupported',
      );
    });
  });

  describe('close', () => {
    test('Client should be destroyed', async () => {
      const client = new KMSClient({});
      const mockDestroy = jest.spyOn(client, 'destroy').mockReturnValue(undefined);
      const provider = new AwsKmsRsaPssProvider(client);

      await provider.close();

      expect(mockDestroy).toHaveBeenCalledWith();
    });
  });
});
