import { Crypto } from '@peculiar/webcrypto';

import { HashingAlgorithm } from '../algorithms';

const NODEJS_CRYPTO = new Crypto();

export function derDeserialisePublicKey(
  publicKeySerialized: ArrayBuffer,
  algorithm: RsaHashedImportParams,
): Promise<CryptoKey> {
  return NODEJS_CRYPTO.subtle.importKey('spki', publicKeySerialized, algorithm, true, ['verify']);
}

export async function hash(input: ArrayBuffer, algorithm: HashingAlgorithm): Promise<ArrayBuffer> {
  return NODEJS_CRYPTO.subtle.digest(algorithm, input);
}
