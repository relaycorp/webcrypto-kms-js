import { NODEJS_CRYPTO, RSA_PSS_SIGN_ALGORITHM } from '../testUtils/webcrypto';

export const PLAINTEXT = Buffer.from('this is the plaintext');

export async function verifyAsymmetricSignature(
  publicKey: CryptoKey,
  signature: ArrayBuffer,
  plaintext: Buffer,
): Promise<boolean> {
  return await NODEJS_CRYPTO.subtle.verify(
    RSA_PSS_SIGN_ALGORITHM,
    publicKey,
    signature,
    plaintext.buffer,
  );
}
