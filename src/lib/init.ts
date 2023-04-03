import { get as getEnvVar } from 'env-var';

import { KmsError } from './KmsError';

import { GcpKmsConfig } from './gcp/GcpKmsConfig';
import { KmsRsaPssProvider } from './KmsRsaPssProvider';
import { GcpKmsRsaPssProvider } from './gcp/GcpKmsRsaPssProvider';

const INITIALISERS: { readonly [key: string]: () => Promise<KmsRsaPssProvider> } = {
  AWS: initAwsProvider,
  GCP: initGcpProvider,
};

export async function initKmsProviderFromEnv(adapter: string): Promise<KmsRsaPssProvider> {
  const init = INITIALISERS[adapter];
  if (!init) {
    throw new KmsError(`Invalid adapter (${adapter})`);
  }
  return init();
}

export async function initAwsProvider(): Promise<KmsRsaPssProvider> {
  // Avoid import-time side effects (e.g., expensive API calls)
  const { AwsKmsRsaPssProvider } = await import('./aws/AwsKmsRsaPssProvider');
  const { KMSClient } = await import('@aws-sdk/client-kms');
  return new AwsKmsRsaPssProvider(
    new KMSClient({
      endpoint: getEnvVar('AWS_KMS_ENDPOINT').asString(),
      region: getEnvVar('AWS_KMS_REGION').asString(),
    }),
  );
}

export async function initGcpProvider(): Promise<KmsRsaPssProvider> {
  const kmsConfig: GcpKmsConfig = {
    location: getEnvVar('GCP_KMS_LOCATION').required().asString(),
    keyRing: getEnvVar('GCP_KMS_KEYRING').required().asString(),
    protectionLevel: getEnvVar('GCP_KMS_PROTECTION_LEVEL').required().asEnum(['SOFTWARE', 'HSM']),
    destroyScheduledDurationSeconds: getEnvVar(
      'GCP_KMS_DESTROY_SCHEDULED_DURATION_SECONDS',
    ).asIntPositive(),
  };

  // Avoid import-time side effects (e.g., expensive API calls)
  const { KeyManagementServiceClient } = await import('@google-cloud/kms');
  return new GcpKmsRsaPssProvider(new KeyManagementServiceClient(), kmsConfig);
}
