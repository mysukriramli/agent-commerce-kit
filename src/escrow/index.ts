import { z } from 'zod';
import nacl from 'tweetnacl';
import { createHash } from 'node:crypto';

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface EscrowVerificationParams<T> {
  promptId: string;
  deliverable: unknown;
  schema: z.ZodSchema<T>;
  maxLatencyMs: number;
  actualLatencyMs: number;
  signingKeyPair: KeyPair;
}

export interface JsonLdAuditRecord {
  "@context": string;
  "@type": string;
  promptId: string;
  verifiedAt: string;
  passed: boolean;
  latencyMs: number;
  deliverableHash: string;
  releaseSignatureHex?: string;
  signerPublicKeyHex?: string;
  validationErrors?: string[];
}

export interface EscrowReleaseResult<T> {
  success: boolean;
  data?: T;
  auditRecord: JsonLdAuditRecord;
  releaseTokenHex?: string;
}

export class DeliverableEscrowEngine {
  private static sha256Hex(data: string): string {
    return createHash('sha256').update(data).digest('hex');
  }

  private static toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  public static async verifyAndRelease<T>(
    params: EscrowVerificationParams<T>
  ): Promise<EscrowReleaseResult<T>> {
    const serializedDeliverable = JSON.stringify(params.deliverable ?? {});
    const deliverableHash = this.sha256Hex(serializedDeliverable);

    // 1. Check Latency SLA
    if (params.actualLatencyMs > params.maxLatencyMs) {
      const auditRecord: JsonLdAuditRecord = {
        "@context": "https://schema.org/v1",
        "@type": "EscrowSettlementVerification",
        promptId: params.promptId,
        verifiedAt: new Date().toISOString(),
        passed: false,
        latencyMs: params.actualLatencyMs,
        deliverableHash,
        validationErrors: [
          `Latency SLA breached: Actual ${params.actualLatencyMs}ms exceeded max limit of ${params.maxLatencyMs}ms`,
        ],
      };
      return { success: false, auditRecord };
    }

    // 2. Validate Schema Structure
    const parseResult = params.schema.safeParse(params.deliverable);
    if (!parseResult.success) {
      const errorMessages = parseResult.error.errors.map(
        (err) => `[${err.path.join('.') || 'root'}]: ${err.message}`
      );

      const auditRecord: JsonLdAuditRecord = {
        "@context": "https://schema.org/v1",
        "@type": "EscrowSettlementVerification",
        promptId: params.promptId,
        verifiedAt: new Date().toISOString(),
        passed: false,
        latencyMs: params.actualLatencyMs,
        deliverableHash,
        validationErrors: errorMessages,
      };
      return { success: false, auditRecord };
    }

    // 3. Cryptographically Sign Deliverable Hash with Ed25519
    const payloadToSign = new TextEncoder().encode(`${params.promptId}:${deliverableHash}`);
    const signature = nacl.sign.detached(payloadToSign, params.signingKeyPair.secretKey);
    const releaseSignatureHex = this.toHex(signature);
    const signerPublicKeyHex = this.toHex(params.signingKeyPair.publicKey);

    const auditRecord: JsonLdAuditRecord = {
      "@context": "https://schema.org/v1",
      "@type": "EscrowSettlementVerification",
      promptId: params.promptId,
      verifiedAt: new Date().toISOString(),
      passed: true,
      latencyMs: params.actualLatencyMs,
      deliverableHash,
      releaseSignatureHex,
      signerPublicKeyHex,
    };

    return {
      success: true,
      data: parseResult.data,
      auditRecord,
      releaseTokenHex: releaseSignatureHex,
    };
  }

  public static generateKeyPair(): KeyPair {
    return nacl.sign.keyPair();
  }
}
