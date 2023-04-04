import { RsaPssProvider } from 'webcrypto-core';

export abstract class KmsRsaPssProvider extends RsaPssProvider {
  public abstract close(): Promise<void>;
}
