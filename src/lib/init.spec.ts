import { EnvVarError } from 'env-var';

import { configureMockEnvVars } from '../testUtils/envVars';
import { initKmsProviderFromEnv } from './init';
import { GcpKmsConfig } from './gcp/GcpKmsConfig';
import { KmsError } from './KmsError';

class MockGcpKeyManagementServiceClient {}

let gcpSdkImported = false;
jest.mock('@google-cloud/kms', () => {
  gcpSdkImported = true;
  return {
    KeyManagementServiceClient: MockGcpKeyManagementServiceClient,
  };
});
beforeEach(() => {
  gcpSdkImported = false;
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
    mockEnvVars(GCP_REQUIRED_ENV_VARS);

    await initKmsProviderFromEnv('GCP');

    expect(gcpSdkImported).toBeTrue();
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

    test('Key store should be returned if env vars are present', async () => {
      const provider = await initKmsProviderFromEnv('GCP');

      const { GcpKmsRsaPssProvider } = await import('./gcp/GcpKmsRsaPssProvider');
      expect(provider).toBeInstanceOf(GcpKmsRsaPssProvider);
      expect(provider).toHaveProperty('client', expect.any(MockGcpKeyManagementServiceClient));
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
});
