import { KeyManagementServiceClient } from '@google-cloud/kms';

export async function createKeyRingIfMissing(keyRingId: string, location: string): Promise<string> {
  const kmsClient = new KeyManagementServiceClient();
  const project = await kmsClient.getProjectId();
  const keyRingName = kmsClient.keyRingPath(project, location, keyRingId);
  try {
    await kmsClient.getKeyRing({ name: keyRingName });
  } catch (err) {
    if ((err as any).code !== 5) {
      throw err;
    }

    // Key ring was not found
    const locationPath = kmsClient.locationPath(project, location);
    await kmsClient.createKeyRing({ parent: locationPath, keyRingId });
  }

  await kmsClient.close();
  return keyRingName;
}
