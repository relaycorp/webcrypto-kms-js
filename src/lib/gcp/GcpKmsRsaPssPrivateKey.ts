import { GcpKmsRsaPssProvider } from './GcpKmsRsaPssProvider';
import { RsaPssPrivateKey } from '../PrivateKey';
import { HashingAlgorithm } from '../algorithms.js';

export class GcpKmsRsaPssPrivateKey extends RsaPssPrivateKey {
  constructor(
    public kmsKeyVersionPath: string,
    hashingAlgorithm: HashingAlgorithm,
    provider: GcpKmsRsaPssProvider,
  ) {
    super(hashingAlgorithm, provider);
  }
}
