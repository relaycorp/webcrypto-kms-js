import { KeyManagementServiceClient } from '@google-cloud/kms';
import { calculate as calculateCRC32C } from 'fast-crc32c';
import { CryptoKey, RsaPssProvider } from 'webcrypto-core';
import uuid4 from 'uuid4';

import { bufferToArrayBuffer } from '../utils/buffer';
import { KmsError } from '../KmsError';
import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';
import { KMS_REQUEST_OPTIONS, wrapGCPCallError } from './kmsUtils';
import { sleep } from '../utils/timing';
import { GcpKmsConfig } from './GcpKmsConfig';
import { NODEJS_CRYPTO } from '../utils/crypto';
import { HashingAlgorithm } from '../algorithms';

// See: https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
const SUPPORTED_MODULUS_LENGTHS = [2048, 3072, 4096];

// See: https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
const SUPPORTED_SALT_LENGTHS: readonly number[] = [
  256 / 8, // SHA-256
  512 / 8, // SHA-512
];

const DEFAULT_DESTROY_SCHEDULED_DURATION_SECONDS = 86_400; // One day; the minimum allowed by GCP

export class GcpKmsRsaPssProvider extends RsaPssProvider {
  constructor(public kmsClient: KeyManagementServiceClient, protected kmsConfig: GcpKmsConfig) {
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
    const kmsAlgorithm = getKmsAlgorithm(algorithm);
    const keyRingName = this.kmsClient.keyRingPath(
      projectId,
      this.kmsConfig.location,
      this.kmsConfig.keyRing,
    );
    const destroyScheduledDuration = {
      seconds:
        this.kmsConfig.destroyScheduledDurationSeconds ??
        DEFAULT_DESTROY_SCHEDULED_DURATION_SECONDS,
    };
    await wrapGCPCallError(
      this.kmsClient.createCryptoKey(
        {
          cryptoKey: {
            destroyScheduledDuration,
            purpose: 'ASYMMETRIC_SIGN',
            versionTemplate: {
              algorithm: kmsAlgorithm as any,
              protectionLevel: this.kmsConfig.protectionLevel,
            },
          },
          cryptoKeyId,
          parent: keyRingName,
          skipInitialVersionCreation: false,
        },
        KMS_REQUEST_OPTIONS,
      ),
      'Failed to create key',
    );

    const kmsKeyVersionPath = this.kmsClient.cryptoKeyVersionPath(
      projectId,
      this.kmsConfig.location,
      this.kmsConfig.keyRing,
      cryptoKeyId,
      '1',
    );

    const privateKey = new GcpKmsRsaPssPrivateKey(
      kmsKeyVersionPath,
      (algorithm.hash as KeyAlgorithm).name as HashingAlgorithm,
      this,
    );
    const publicKeySerialized = (await this.exportKey('spki', privateKey)) as ArrayBuffer;
    const publicKey = await NODEJS_CRYPTO.subtle.importKey(
      'spki',
      publicKeySerialized,
      algorithm,
      true,
      ['verify'],
    );

    return { privateKey, publicKey };
  }

  public async onImportKey(): Promise<CryptoKey> {
    throw new KmsError('Key import is unsupported');
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer> {
    if (format !== 'spki') {
      throw new KmsError('Private key cannot be exported');
    }
    if (!(key instanceof GcpKmsRsaPssPrivateKey)) {
      throw new KmsError('Key is not managed by KMS');
    }
    return retrieveKMSPublicKey(key.kmsKeyVersionPath, this.kmsClient);
  }

  public async onSign(
    algorithm: RsaPssParams,
    key: CryptoKey,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    if (!(key instanceof GcpKmsRsaPssPrivateKey)) {
      throw new KmsError(`Cannot sign with key of unsupported type (${key.constructor.name})`);
    }

    if (!SUPPORTED_SALT_LENGTHS.includes(algorithm.saltLength)) {
      throw new KmsError(`Unsupported salt length of ${algorithm.saltLength} octets`);
    }

    return this.kmsSign(Buffer.from(data), key);
  }

  public async onVerify(): Promise<boolean> {
    throw new KmsError('Signature verification is unsupported');
  }

  private async getGCPProjectId(): Promise<string> {
    // GCP client library already caches the project id.
    return this.kmsClient.getProjectId();
  }

  private async kmsSign(plaintext: Buffer, key: GcpKmsRsaPssPrivateKey): Promise<ArrayBuffer> {
    const plaintextChecksum = calculateCRC32C(plaintext);
    const [response] = await wrapGCPCallError(
      this.kmsClient.asymmetricSign(
        { data: plaintext, dataCrc32c: { value: plaintextChecksum }, name: key.kmsKeyVersionPath },
        KMS_REQUEST_OPTIONS,
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

function getKmsAlgorithm(algorithm: RsaHashedKeyGenParams) {
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
