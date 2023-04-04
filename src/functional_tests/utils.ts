import { constants, createVerify } from 'crypto';

import { derSerializePublicKey } from '../testUtils/webcrypto';
import { derPublicKeyToPem } from '../testUtils/asn1';

export const PLAINTEXT = Buffer.from('this is the plaintext');

export async function verifyAsymmetricSignature(
  publicKey: CryptoKey,
  signature: ArrayBuffer,
  plaintext: Buffer,
): Promise<boolean> {
  const verify = createVerify('sha256');
  verify.update(plaintext);
  verify.end();

  const publicKeyDer = await derSerializePublicKey(publicKey);
  return verify.verify(
    { key: derPublicKeyToPem(publicKeyDer), padding: constants.RSA_PKCS1_PSS_PADDING },
    new Uint8Array(signature),
  );
}
