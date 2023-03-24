import { CreateKeyCommand, KeyUsageType, KMSClient } from '@aws-sdk/client-kms';
import { CryptoKey } from 'webcrypto-core';

import { KmsRsaPssProvider } from '../KmsRsaPssProvider';
import { AwsKmsRsaPssPrivateKey } from './AwsKmsRsaPssPrivateKey';
import { KmsError } from '../KmsError';
import { HashingAlgorithm } from '../algorithms';

// See: https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html
const SUPPORTED_MODULUS_LENGTHS: readonly number[] = [2048, 3072, 4096];

const REQUEST_OPTIONS = { requestTimeout: 3_000 };

export class AwsKmsRsaPssProvider extends KmsRsaPssProvider {
  constructor(protected readonly client: KMSClient) {
    super();

    // See: https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html
    this.hashAlgorithms = ['SHA-256', 'SHA-384', 'SHA-512'];
  }

  async onGenerateKey(algorithm: RsaHashedKeyGenParams): Promise<CryptoKeyPair> {
    if (!SUPPORTED_MODULUS_LENGTHS.includes(algorithm.modulusLength)) {
      throw new KmsError(`Unsupported RSA modulus (${algorithm.modulusLength})`);
    }

    const keySpec = `RSA_${algorithm.modulusLength}`;
    const command = new CreateKeyCommand({
      KeySpec: keySpec,
      KeyUsage: KeyUsageType.SIGN_VERIFY,
    });

    const response = await this.client.send(command, REQUEST_OPTIONS);

    const keyArn = response.KeyMetadata?.Arn;
    if (!keyArn) {
      throw new KmsError('Key creation response is missing KeyMetadata.Arn');
    }
    const privateKey = new AwsKmsRsaPssPrivateKey(
      keyArn,
      (algorithm.hash as KeyAlgorithm).name as HashingAlgorithm,
      this,
    );

    return { privateKey, publicKey: {} as any };
  }

  onImportKey(
    _format: KeyFormat,
    _keyData: ArrayBuffer | JsonWebKey,
    _algorithm: RsaHashedImportParams,
    _extractable: boolean,
    _keyUsages: KeyUsage[],
  ): Promise<CryptoKey> {
    throw new Error('Method not implemented.');
  }

  onExportKey(_format: KeyFormat, _key: CryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    throw new Error('Method not implemented.');
  }

  onSign(_algorithm: RsaPssParams, _key: CryptoKey, _data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error('Method not implemented.');
  }

  onVerify(
    _algorithm: RsaPssParams,
    _key: CryptoKey,
    _signature: ArrayBuffer,
    _data: ArrayBuffer,
  ): Promise<boolean> {
    throw new Error('Method not implemented.');
  }
}
