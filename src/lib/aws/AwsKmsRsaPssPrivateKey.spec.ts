import { AwsKmsRsaPssPrivateKey } from './AwsKmsRsaPssPrivateKey';
import { AwsKmsRsaPssProvider } from './AwsKmsRsaPssProvider';
import { HashingAlgorithm } from '../algorithms';

const HASHING_ALGORITHM: HashingAlgorithm = 'SHA-256';
const KMS_KEY_ARN = 'arn:aws:kms:eu-west-2:111122223333:key/c34c7f46-e663-4d76-bff4-7b5c0820e500';
const KMS_PROVIDER = new AwsKmsRsaPssProvider();

test('KMS key ARN should be honored', () => {
  const key = new AwsKmsRsaPssPrivateKey(KMS_KEY_ARN, HASHING_ALGORITHM, KMS_PROVIDER);

  expect(key.arn).toEqual(KMS_KEY_ARN);
});

test('Crypto provider should be honored', () => {
  const key = new AwsKmsRsaPssPrivateKey(KMS_KEY_ARN, HASHING_ALGORITHM, KMS_PROVIDER);

  expect(key.provider).toBe(KMS_PROVIDER);
});

test('Hashing algorithm should be honored', () => {
  const key = new AwsKmsRsaPssPrivateKey(KMS_KEY_ARN, HASHING_ALGORITHM, KMS_PROVIDER);

  expect(key.algorithm).toHaveProperty('hash.name', HASHING_ALGORITHM);
});
