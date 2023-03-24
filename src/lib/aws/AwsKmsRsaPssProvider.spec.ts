import {
  CreateKeyCommand,
  CreateKeyCommandOutput,
  KeyUsageType,
  KMSClient,
} from '@aws-sdk/client-kms';

import { AwsKmsRsaPssProvider } from './AwsKmsRsaPssProvider';
import {
  HASHING_ALGORITHM,
  KEY_USAGES,
  RSA_PSS_CREATION_ALGORITHM,
} from '../../testUtils/webcrypto';
import { KmsError } from '../KmsError';
import { AwsKmsRsaPssPrivateKey } from './AwsKmsRsaPssPrivateKey';
import { getMockInstance } from '../../testUtils/jest';

const AWS_KMS_KEY_ID = '24c7110a-af17-43d9-86ab-17294034c3d8';
const AWS_KMS_KEY_ARN = `arn:aws:kms:eu-west-2:111122223333:key/${AWS_KMS_KEY_ID}`;

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
      test.todo('Public key should match private key');

      test.todo('Key algorithm should be populated correctly');

      test.todo('Key should be extractable');

      test.todo('Key usages should only include "verify"');
    });

    function makeAwsClient(): KMSClient {
      const client = new KMSClient({});
      const response: CreateKeyCommandOutput = {
        $metadata: {},
        KeyMetadata: {
          Arn: AWS_KMS_KEY_ARN,
          KeyId: AWS_KMS_KEY_ID,
        },
      };
      jest.spyOn<KMSClient, any>(client, 'send').mockResolvedValue(response);
      return client;
    }
  });

  describe('hashingAlgorithms', () => {
    test('Only SHA-256, SHA-384 and SHA-512 should be supported', async () => {
      const provider = new AwsKmsRsaPssProvider(null as any);

      expect(provider.hashAlgorithms).toEqual(['SHA-256', 'SHA-384', 'SHA-512']);
    });
  });
});
