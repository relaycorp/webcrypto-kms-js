export type ProtectionLevel = 'SOFTWARE' | 'HSM';

export interface GcpKmsConfig {
  readonly location: string;
  readonly keyRing: string;
  readonly protectionLevel: ProtectionLevel;
  readonly destroyScheduledDurationSeconds?: number;
}
