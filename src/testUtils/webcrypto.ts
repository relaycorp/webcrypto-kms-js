import { Crypto } from '@peculiar/webcrypto';
import { KeyAlgorithm } from 'webcrypto-core';

const NODEJS_CRYPTO = new Crypto();

export const HASHING_ALGORITHM_NAME = 'SHA-256';
export const HASHING_ALGORITHM: KeyAlgorithm = { name: HASHING_ALGORITHM_NAME };
export const RSA_PSS_CREATION_ALGORITHM: RsaHashedKeyGenParams = {
  name: 'RSA-PSS',
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: HASHING_ALGORITHM,
};

export async function derSerializePublicKey(publicKey: CryptoKey): Promise<Buffer> {
  const publicKeyDer = await NODEJS_CRYPTO.subtle.exportKey('spki', publicKey);
  return Buffer.from(publicKeyDer);
}

// tslint:disable-next-line:readonly-array
export const KEY_USAGES: KeyUsage[] = ['sign'];
