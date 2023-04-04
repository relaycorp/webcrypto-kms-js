import { RsaPssProvider } from 'webcrypto-core';

export abstract class KmsRsaPssProvider extends RsaPssProvider {
  public abstract destroyKey(key: CryptoKey): Promise<void>;

  public abstract close(): Promise<void>;
}
