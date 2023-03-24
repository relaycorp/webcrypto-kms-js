import { Crypto } from '@peculiar/webcrypto';

const NODEJS_CRYPTO = new Crypto();

export function derDeserialisePublicKey(
  publicKeySerialized: ArrayBuffer,
  algorithm: RsaHashedImportParams,
): Promise<CryptoKey> {
  return NODEJS_CRYPTO.subtle.importKey('spki', publicKeySerialized, algorithm, true, ['verify']);
}
