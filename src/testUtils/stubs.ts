import { bufferToArrayBuffer } from '../lib/utils/buffer';

/**
 * Real public keys exported from their respective KMSs.
 *
 * Copied here to avoid interoperability issues -- namely around the serialisation of
 * `AlgorithmParams` (`NULL` vs absent).
 */
export const REAL_PUBLIC_KEYS = {
  aws: Buffer.from(
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwjvvzL+iVL3bohN4aFfNDk5EtGdJQPGJM3BfRU9gg7zc+a' +
      'nJJO8/Q3d/lzHadyyilazC3d67bcrQoc7RHialsq6CzuVLUB68p2ktGPuUA4W+bSCprKase+fkjXrPWCW+ZCzfi78o' +
      'EsGPCoVNNvejiTBF+G0XmspiKI6IzOCQVEgipVD8mJaApBixbjsaD72snIxH62fR1aaLPQ8ePB0Dku+YzAXAN/SRWf' +
      'cTxDph2Vtm2Q3Lq/5xqFsa2aNDkgfk5E/Yx3jsnYI+Ed1y/iAu4MZ19GIGa6yjHSlIQwq1HQeLyb07K0rg4qe5nUSc' +
      'I+NKkH3s0Va1vAgQKEGshkQS+QIDAQAB',
    'base64',
  ),
  gcp: Buffer.from(
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnL8hQlf3GLajYh5NA6k7bpHPYUxjiZJgOEiDs8y1iPa6p' +
      '/40p6OeFAakIgqNBZS4CfWnZQ8fPJxCN3ctRMOXQqyajkXHqcUO07shjlvJA9niPQfqpLF2izdSimqMdZkPDfOs4Q' +
      '254+ZLld/JpGn4CocYMaACXWrT+sY4CWw0EJh2kWKcEWF9Z5TL7wA+mJyHZN/cTndIM1kORb8ADzNfyBPMhGRp31N' +
      '4dLff0H28MQCr/0GPbAA+5dMReCPTMLollAI4JmaNtYEaw32sSsH35POtfVz91ui5AaxVONapfw4NfLrxdBvySBhZ' +
      'Zq76INzyG6uwx7TDqJwy0e+SLmF4mQIDAQAB',
    'base64',
  ),
} as const;

export const PLAINTEXT = bufferToArrayBuffer(Buffer.from('the plaintext'));

export const SIGNATURE = Buffer.from('the signature');
