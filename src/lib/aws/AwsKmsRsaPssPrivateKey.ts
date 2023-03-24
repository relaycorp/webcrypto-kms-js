import type { AwsKmsRsaPssProvider } from './AwsKmsRsaPssProvider';
import { RsaPssPrivateKey } from '../PrivateKey';
import { HashingAlgorithm } from '../algorithms';

export class AwsKmsRsaPssPrivateKey extends RsaPssPrivateKey<AwsKmsRsaPssProvider> {
  constructor(
    public arn: string,
    hashingAlgorithm: HashingAlgorithm,
    provider: AwsKmsRsaPssProvider,
  ) {
    super(hashingAlgorithm, provider);
  }
}
