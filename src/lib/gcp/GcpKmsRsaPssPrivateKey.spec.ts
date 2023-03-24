import { GcpKmsRsaPssPrivateKey } from './GcpKmsRsaPssPrivateKey';
import { GcpKmsRsaPssProvider } from './GcpKmsRsaPssProvider';
import { HashingAlgorithm } from '../algorithms';

const HASHING_ALGORITHM: HashingAlgorithm = 'SHA-256';
const KMS_KEY_PATH = 'projects/foo/key/42';
const KMS_PROVIDER = new GcpKmsRsaPssProvider(null as any, null as any);

test('KMS key path should be honored', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, HASHING_ALGORITHM, KMS_PROVIDER);

  expect(key.kmsKeyVersionPath).toEqual(KMS_KEY_PATH);
});

test('Crypto provider should be honored', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, HASHING_ALGORITHM, KMS_PROVIDER);

  expect(key.provider).toBe(KMS_PROVIDER);
});

test('Hashing algorithm should be honored', () => {
  const key = new GcpKmsRsaPssPrivateKey(KMS_KEY_PATH, HASHING_ALGORITHM, KMS_PROVIDER);

  expect(key.algorithm).toHaveProperty('hash.name', HASHING_ALGORITHM);
});
