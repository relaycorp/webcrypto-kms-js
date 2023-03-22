import { catchPromiseRejection } from '../../testUtils/promises';
import { KmsError } from '../KmsError';
import { wrapGCPCallError } from './kmsUtils';

describe('wrapGCPCallError', () => {
  const gcpError = new Error('Someone talked about Bruno');

  test('Successful calls should resolve', async () => {
    const resolvedValue = 42;

    await expect(wrapGCPCallError(Promise.resolve(resolvedValue), '')).resolves.toEqual(
      resolvedValue,
    );
  });

  test('Failed calls should be wrapped in custom error', async () => {
    await expect(wrapGCPCallError(Promise.reject(gcpError), '')).rejects.toBeInstanceOf(KmsError);
  });

  test('Wrapping exception should use specified error message', async () => {
    const errorMessage = 'The error message';

    const error = await catchPromiseRejection(
      wrapGCPCallError(Promise.reject(gcpError), errorMessage),
      KmsError,
    );

    expect(error.message).toEqual(errorMessage);
  });

  test('Wrapped exception should be original one from GCP API client', async () => {
    const error = await catchPromiseRejection(
      wrapGCPCallError(Promise.reject(gcpError), ''),
      KmsError,
    );

    expect(error.cause).toEqual(gcpError);
  });
});
