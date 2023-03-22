import { KmsError } from '../KmsError';

/**
 * The official KMS library will often try to make API requests before the authentication with the
 * Application Default Credentials is complete, which will result in errors like "Exceeded
 * maximum number of retries before any response was received". We're working around that by
 * retrying a few times.
 */
export const KMS_REQUEST_OPTIONS = { timeout: 3_000, maxRetries: 10 };

/**
 * Wrap GCP API call errors
 *
 * To provide a useful stack trace and error message, which we don't get with GCP library errors.
 *
 * @param callPromise
 * @param errorMessage
 */
export async function wrapGCPCallError<T>(
  callPromise: Promise<T>,
  errorMessage: string,
): Promise<T> {
  try {
    return await callPromise;
  } catch (err) {
    throw new KmsError(errorMessage, { cause: err });
  }
}
