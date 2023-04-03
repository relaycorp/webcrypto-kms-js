/* tslint:disable:max-classes-per-file */
import { EnvVarError } from 'env-var';

import { configureMockEnvVars } from '../testUtils/envVars';
import { initKmsProviderFromEnv } from './init';
import { GcpKmsConfig } from './gcp/GcpKmsConfig';
import { KmsError } from './KmsError';

class MockGcpSdkClient {}

class MockAwsSdkClient {
  constructor(public readonly config: any) {}
}

let gcpSdkImported = false;
jest.mock('@google-cloud/kms', () => {
  gcpSdkImported = true;
  return {
    KeyManagementServiceClient: MockGcpSdkClient,
  };
});
let awsSdkImported = false;
jest.mock('@aws-sdk/client-kms', () => {
  awsSdkImported = true;
  return { ...jest.requireActual('@aws-sdk/client-kms'), KMSClient: MockAwsSdkClient };
});
beforeEach(() => {
  gcpSdkImported = false;
  awsSdkImported = false;
});

describe('initKmsProviderFromEnv', () => {
  const mockEnvVars = configureMockEnvVars();

  const GCP_REQUIRED_ENV_VARS = {
    GCP_KMS_LOCATION: 'westeros-3',
    GCP_KMS_KEYRING: 'my-precious',
    GCP_KMS_PROTECTION_LEVEL: 'HSM',
  } as const;

  test('Unknown adapter should be refused', async () => {
    const invalidAdapter = 'potato';
    await expect(() => initKmsProviderFromEnv(invalidAdapter as any)).rejects.toThrowWithMessage(
      KmsError,
      `Invalid adapter (${invalidAdapter})`,
    );
  });

  test('Adapters should be imported lazily', async () => {
    expect(gcpSdkImported).toBeFalse();
    expect(awsSdkImported).toBeFalse();

    mockEnvVars(GCP_REQUIRED_ENV_VARS);
    await initKmsProviderFromEnv('GCP');
    expect(gcpSdkImported).toBeTrue();
    expect(awsSdkImported).toBeFalse();

    await initKmsProviderFromEnv('AWS');
    expect(awsSdkImported).toBeTrue();
  });

  describe('GPC', () => {
    beforeEach(() => {
      mockEnvVars(GCP_REQUIRED_ENV_VARS);
    });

    test.each(Object.getOwnPropertyNames(GCP_REQUIRED_ENV_VARS))(
      'Environment variable %s should be present',
      async (envVar) => {
        mockEnvVars({ ...GCP_REQUIRED_ENV_VARS, [envVar]: undefined });

        await expect(initKmsProviderFromEnv('GCP')).rejects.toThrowWithMessage(
          EnvVarError,
          new RegExp(envVar),
        );
      },
    );

    test('Provider should be returned if env vars are present', async () => {
      const provider = await initKmsProviderFromEnv('GCP');

      const { GcpKmsRsaPssProvider } = await import('./gcp/GcpKmsRsaPssProvider');
      expect(provider).toBeInstanceOf(GcpKmsRsaPssProvider);
      expect(provider).toHaveProperty('client', expect.any(MockGcpSdkClient));
      expect(provider).toHaveProperty<GcpKmsConfig>('config', {
        keyRing: GCP_REQUIRED_ENV_VARS.GCP_KMS_KEYRING,
        location: GCP_REQUIRED_ENV_VARS.GCP_KMS_LOCATION,
        protectionLevel: GCP_REQUIRED_ENV_VARS.GCP_KMS_PROTECTION_LEVEL,
      });
    });

    test('GCP_KMS_DESTROY_SCHEDULED_DURATION_SECONDS should be honoured if set', async () => {
      const seconds = 123;
      mockEnvVars({
        ...GCP_REQUIRED_ENV_VARS,
        GCP_KMS_DESTROY_SCHEDULED_DURATION_SECONDS: seconds.toString(),
      });

      const provider = await initKmsProviderFromEnv('GCP');

      expect(provider).toHaveProperty('config.destroyScheduledDurationSeconds', seconds);
    });

    test('Invalid GCP_KMS_PROTECTION_LEVEL should be refused', async () => {
      mockEnvVars({ ...GCP_REQUIRED_ENV_VARS, GCP_KMS_PROTECTION_LEVEL: 'potato' });

      await expect(initKmsProviderFromEnv('GCP')).rejects.toThrowWithMessage(
        EnvVarError,
        /GCP_KMS_PROTECTION_LEVEL/,
      );
    });
  });

  describe('AWS', () => {
    test('AWS KMS provider should be output', async () => {
      const provider = await initKmsProviderFromEnv('AWS');

      const { AwsKmsRsaPssProvider } = await import('./aws/AwsKmsRsaPssProvider');
      expect(provider).toBeInstanceOf(AwsKmsRsaPssProvider);
      expect(provider).toHaveProperty('client.config', {
        endpoint: undefined,
        region: undefined,
      });
    });

    test('AWS_KMS_ENDPOINT should be honoured if present', async () => {
      const endpoint = 'https://kms.example.com';
      mockEnvVars({ AWS_KMS_ENDPOINT: endpoint });

      const provider = await initKmsProviderFromEnv('AWS');

      expect(provider).toHaveProperty('client.config.endpoint', endpoint);
    });

    test('AWS_KMS_REGION should be honoured if present', async () => {
      const region = 'westeros-3';
      mockEnvVars({ AWS_KMS_REGION: region });

      const provider = await initKmsProviderFromEnv('AWS');

      expect(provider).toHaveProperty('client.config.region', region);
    });
  });
});
