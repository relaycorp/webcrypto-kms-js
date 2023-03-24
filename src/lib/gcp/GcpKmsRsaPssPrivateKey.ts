import type { GcpKmsRsaPssProvider } from './GcpKmsRsaPssProvider';
import { RsaPssPrivateKey } from '../PrivateKey';
import { HashingAlgorithm } from '../algorithms';

export class GcpKmsRsaPssPrivateKey extends RsaPssPrivateKey<GcpKmsRsaPssProvider> {
  constructor(
    public kmsKeyVersionPath: string,
    hashingAlgorithm: HashingAlgorithm,
    provider: GcpKmsRsaPssProvider,
  ) {
    super(hashingAlgorithm, provider);
  }
}
