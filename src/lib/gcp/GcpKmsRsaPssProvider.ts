import type { KeyManagementServiceClient } from '@google-cloud/kms';
import { calculate as calculateCRC32C } from 'fast-crc32c';
import { CryptoKey } from 'webcrypto-core';
import uuid4 from 'uuid4';

import { bufferToArrayBuffer } from '../utils/buffer';
import { KmsError } from '../KmsError';
import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';
import { wrapGCPCallError } from './kmsUtils';
import { sleep } from '../utils/timing';
import { GcpKmsConfig } from './GcpKmsConfig';
import { derDeserialisePublicKey } from '../utils/crypto';
import { HashingAlgorithm } from '../algorithms';
import { KmsRsaPssProvider } from '../KmsRsaPssProvider';

// See: https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
const SUPPORTED_MODULUS_LENGTHS: readonly number[] = [2048, 3072, 4096];

// See: https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
const SUPPORTED_SALT_LENGTHS: readonly number[] = [
  256 / 8, // SHA-256
  512 / 8, // SHA-512
];

const DEFAULT_DESTROY_SCHEDULED_DURATION_SECONDS = 86_400; // One day; the minimum allowed by GCP

/**
 * The official KMS library will often try to make API requests before the authentication with the
 * Application Default Credentials is complete, which will result in errors like "Exceeded
 * maximum number of retries before any response was received". We're working around that by
 * retrying a few times.
 */
const REQUEST_OPTIONS = { timeout: 3_000, maxRetries: 10 };

export class GcpKmsRsaPssProvider extends KmsRsaPssProvider {
  constructor(public client: KeyManagementServiceClient, public config: GcpKmsConfig) {
    super();

    // See: https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
    this.hashAlgorithms = ['SHA-256', 'SHA-512'];
  }

  public async onGenerateKey(algorithm: RsaHashedKeyGenParams): Promise<CryptoKeyPair> {
    if (!SUPPORTED_MODULUS_LENGTHS.includes(algorithm.modulusLength)) {
      throw new KmsError(`Unsupported RSA modulus (${algorithm.modulusLength})`);
    }

    const projectId = await this.getGCPProjectId();

    const cryptoKeyId = uuid4();
    await this.createCryptoKey(algorithm, projectId, cryptoKeyId);

    const kmsKeyVersionPath = this.client.cryptoKeyVersionPath(
      projectId,
      this.config.location,
      this.config.keyRing,
      cryptoKeyId,
      '1',
    );
    const privateKey = new GcpKmsRsaPssPrivateKey(
      kmsKeyVersionPath,
      (algorithm.hash as KeyAlgorithm).name as HashingAlgorithm,
      this,
    );
    const publicKey = await this.getPublicKeyFromPrivate(privateKey);
    return { privateKey, publicKey };
  }

  public async onImportKey(
    format: KeyFormat,
    keyData: ArrayBuffer,
    algorithm: RsaHashedImportParams,
  ): Promise<CryptoKey> {
    if (format !== 'raw') {
      throw new KmsError('Private key can only be exported to raw format');
    }

    const kmsKeyVersionPath = Buffer.from(keyData).toString();
    return new GcpKmsRsaPssPrivateKey(
      kmsKeyVersionPath,
      (algorithm.hash as KeyAlgorithm).name as HashingAlgorithm,
      this,
    );
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer> {
    requireGcpKmsKey(key);

    let keySerialised: ArrayBuffer;
    if (format === 'spki') {
      keySerialised = await retrieveKMSPublicKey(key.kmsKeyVersionPath, this.client);
    } else if (format === 'raw') {
      const pathEncoded = Buffer.from(key.kmsKeyVersionPath);
      keySerialised = bufferToArrayBuffer(pathEncoded);
    } else {
      throw new KmsError(`Private key cannot be exported as ${format}`);
    }
    return keySerialised;
  }

  public async onSign(
    algorithm: RsaPssParams,
    key: CryptoKey,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    requireGcpKmsKey(key);

    if (!SUPPORTED_SALT_LENGTHS.includes(algorithm.saltLength)) {
      throw new KmsError(`Unsupported salt length of ${algorithm.saltLength} octets`);
    }

    return this.kmsSign(Buffer.from(data), key);
  }

  public async onVerify(): Promise<boolean> {
    throw new KmsError('Signature verification is unsupported');
  }

  public async destroyKey(key: CryptoKey): Promise<void> {
    requireGcpKmsKey(key);

    await wrapGCPCallError(
      this.client.destroyCryptoKeyVersion({ name: key.kmsKeyVersionPath }, REQUEST_OPTIONS),
      'Key destruction failed',
    );
  }

  public async close(): Promise<void> {
    await this.client.close();
  }

  private async getGCPProjectId(): Promise<string> {
    // GCP client library already caches the project id.
    return this.client.getProjectId();
  }

  private async createCryptoKey(
    algorithm: RsaHashedKeyGenParams,
    projectId: string,
    cryptoKeyId: string,
  ): Promise<void> {
    const kmsAlgorithm = getKmsAlgorithm(algorithm);
    const keyRingName = this.client.keyRingPath(
      projectId,
      this.config.location,
      this.config.keyRing,
    );
    const destroyScheduledDuration = {
      seconds:
        this.config.destroyScheduledDurationSeconds ?? DEFAULT_DESTROY_SCHEDULED_DURATION_SECONDS,
    };
    const creationOptions = {
      cryptoKey: {
        destroyScheduledDuration,
        purpose: 'ASYMMETRIC_SIGN',
        versionTemplate: {
          algorithm: kmsAlgorithm as any,
          protectionLevel: this.config.protectionLevel,
        },
      },
      cryptoKeyId,
      parent: keyRingName,
      skipInitialVersionCreation: false,
    } as const;
    await wrapGCPCallError(
      this.client.createCryptoKey(creationOptions, REQUEST_OPTIONS),
      'Failed to create key',
    );
  }

  private async getPublicKeyFromPrivate(privateKey: GcpKmsRsaPssPrivateKey): Promise<CryptoKey> {
    const publicKeySerialized = (await this.exportKey('spki', privateKey)) as ArrayBuffer;
    return derDeserialisePublicKey(
      publicKeySerialized,
      privateKey.algorithm as RsaHashedImportParams,
    );
  }

  private async kmsSign(plaintext: Buffer, key: GcpKmsRsaPssPrivateKey): Promise<ArrayBuffer> {
    const plaintextChecksum = calculateCRC32C(plaintext);
    const [response] = await wrapGCPCallError(
      this.client.asymmetricSign(
        { data: plaintext, dataCrc32c: { value: plaintextChecksum }, name: key.kmsKeyVersionPath },
        REQUEST_OPTIONS,
      ),
      'KMS signature request failed',
    );

    if (response.name !== key.kmsKeyVersionPath) {
      throw new KmsError(`KMS used the wrong key version (${response.name})`);
    }
    if (!response.verifiedDataCrc32c) {
      throw new KmsError('KMS failed to verify plaintext CRC32C checksum');
    }
    const signature = response.signature as Buffer;
    if (calculateCRC32C(signature) !== Number(response.signatureCrc32c!.value)) {
      throw new KmsError('Signature CRC32C checksum does not match one received from KMS');
    }
    return bufferToArrayBuffer(signature);
  }
}

function requireGcpKmsKey(key: CryptoKey): asserts key is GcpKmsRsaPssPrivateKey {
  if (!(key instanceof GcpKmsRsaPssPrivateKey)) {
    throw new KmsError(`Only GCP KMS keys are supported (got ${key.constructor.name})`);
  }
}

function getKmsAlgorithm(algorithm: RsaHashedKeyGenParams): string {
  const hash = (algorithm.hash as KeyAlgorithm).name === 'SHA-256' ? 'SHA256' : 'SHA512';
  return `RSA_SIGN_PSS_${algorithm.modulusLength}_${hash}`;
}

export async function retrieveKMSPublicKey(
  kmsKeyVersionName: string,
  kmsClient: KeyManagementServiceClient,
): Promise<ArrayBuffer> {
  const retrieveWhenReady = async () => {
    let key: string;
    try {
      key = await _retrieveKMSPublicKey(kmsKeyVersionName, kmsClient);
    } catch (err) {
      if (!isKeyPendingCreation(err as Error)) {
        throw err;
      }

      // Let's give KMS a bit more time to generate the key
      await sleep(500);
      key = await _retrieveKMSPublicKey(kmsKeyVersionName, kmsClient);
    }
    return key;
  };
  const publicKeyPEM = await wrapGCPCallError(retrieveWhenReady(), 'Failed to retrieve public key');
  const publicKeyDer = pemToDer(publicKeyPEM);
  return bufferToArrayBuffer(publicKeyDer);
}

async function _retrieveKMSPublicKey(
  kmsKeyVersionName: string,
  kmsClient: KeyManagementServiceClient,
): Promise<string> {
  const [response] = await kmsClient.getPublicKey(
    { name: kmsKeyVersionName },
    {
      maxRetries: 3,
      timeout: 300,
    },
  );
  return response.pem!;
}

function isKeyPendingCreation(err: Error): boolean {
  const statusDetails = (err as any).statusDetails ?? [];
  const pendingCreationViolations = statusDetails.filter(
    (d: any) => 0 < d.violations.filter((v: any) => v.type === 'KEY_PENDING_GENERATION').length,
  );
  return !!pendingCreationViolations.length;
}

function pemToDer(pemBuffer: string): Buffer {
  const oneliner = pemBuffer.toString().replace(/(-----[\w ]*-----|\n)/g, '');
  return Buffer.from(oneliner, 'base64');
}
