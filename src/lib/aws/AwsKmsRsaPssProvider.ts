import {
  CreateKeyCommand,
  GetPublicKeyCommand,
  KeyUsageType,
  KMSClient,
  SignCommand,
} from '@aws-sdk/client-kms';
import { CryptoKey } from 'webcrypto-core';

import { KmsRsaPssProvider } from '../KmsRsaPssProvider';
import { AwsKmsRsaPssPrivateKey } from './AwsKmsRsaPssPrivateKey';
import { KmsError } from '../KmsError';
import { HashingAlgorithm } from '../algorithms';
import { bufferToArrayBuffer } from '../utils/buffer';
import { derDeserialisePublicKey, hash } from '../utils/crypto';

// See: https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html
const SUPPORTED_MODULUS_LENGTHS: readonly number[] = [2048, 3072, 4096];

const REQUEST_OPTIONS = { requestTimeout: 3_000 };

export class AwsKmsRsaPssProvider extends KmsRsaPssProvider {
  constructor(public readonly client: KMSClient) {
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

    const publicKeySerialised = await this.retrievePublicKey(privateKey);
    const publicKey = await derDeserialisePublicKey(publicKeySerialised, algorithm);

    return { privateKey, publicKey };
  }

  async onExportKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    if (!(key instanceof AwsKmsRsaPssPrivateKey)) {
      throw new KmsError('Key is not managed by AWS KMS');
    }

    let keySerialised: ArrayBuffer;
    if (format === 'raw') {
      const arnEncoded = Buffer.from(key.arn);
      keySerialised = bufferToArrayBuffer(arnEncoded);
    } else if (format === 'spki') {
      keySerialised = await this.retrievePublicKey(key);
    } else {
      throw new KmsError('Private key cannot be exported');
    }

    return keySerialised;
  }

  async onImportKey(
    format: KeyFormat,
    keyData: ArrayBuffer,
    algorithm: RsaHashedImportParams,
  ): Promise<CryptoKey> {
    if (format !== 'raw') {
      throw new KmsError('Private key can only be exported to raw format');
    }

    const keyArn = Buffer.from(keyData).toString();
    return new AwsKmsRsaPssPrivateKey(
      keyArn,
      (algorithm.hash as KeyAlgorithm).name as HashingAlgorithm,
      this,
    );
  }

  async onSign(_algorithm: RsaPssParams, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    if (!(key instanceof AwsKmsRsaPssPrivateKey)) {
      throw new KmsError('Key is not managed by AWS KMS');
    }

    const hashingAlgorithm = (key.algorithm as RsaHashedKeyAlgorithm).hash.name;
    const digest = await hash(data, hashingAlgorithm as HashingAlgorithm);
    const awsHashAlgo = `RSASSA_PSS_${hashingAlgorithm.replace('-', '_')}`;
    const command = new SignCommand({
      KeyId: key.arn,
      Message: Buffer.from(digest),
      MessageType: 'DIGEST',
      SigningAlgorithm: awsHashAlgo,
    });

    const output = await this.client.send(command, REQUEST_OPTIONS);
    return bufferToArrayBuffer(output.Signature!);
  }

  async onVerify(): Promise<boolean> {
    throw new KmsError('Signature verification is unsupported');
  }

  private async retrievePublicKey(key: AwsKmsRsaPssPrivateKey): Promise<ArrayBuffer> {
    const command = new GetPublicKeyCommand({ KeyId: key.arn });
    const response = await this.client.send(command, REQUEST_OPTIONS);
    return bufferToArrayBuffer(response.PublicKey!);
  }
}
