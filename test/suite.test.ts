import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import { Hono } from 'hono';
import { AgentSpendGuard } from '../src/spendguard/index.js';
import { DeliverableEscrowEngine } from '../src/escrow/index.js';
import { x402Paywall } from '../src/paywall/index.js';

describe('Agent Commerce Suite - Core Integration Tests', () => {

  describe('Module 1: Agent Spend-Guard', () => {
    const policy = {
      maxSpendPerCallUsd: 1.0,
      maxHourlySpendUsd: 2.5,
      maxCallsPerHour: 3,
      allowedDomains: ['api.agentpay.network', 'data.provider.com'],
    };

    it('should reject unauthorized target domains', () => {
      const guard = new AgentSpendGuard(policy);
      const res = guard.evaluate({
        targetUrl: 'https://malicious-site.com/drain',
        costUsd: 0.1,
        toolName: 'webScraper',
      });
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('not permitted by policy');
    });

    it('should reject requests exceeding single-call limit', () => {
      const guard = new AgentSpendGuard(policy);
      const res = guard.evaluate({
        targetUrl: 'https://data.provider.com/large-query',
        costUsd: 1.5,
        toolName: 'databaseQuery',
      });
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('exceeds single-call limit');
    });

    it('should correctly track hourly budget across sequential calls', () => {
      const guard = new AgentSpendGuard(policy);

      const firstCall = guard.evaluate({
        targetUrl: 'https://data.provider.com/item1',
        costUsd: 0.8,
        toolName: 'fetch',
      });
      expect(firstCall.allowed).toBe(true);
      expect(firstCall.remainingHourlyBudgetUsd).toBeCloseTo(1.7);

      const secondCall = guard.evaluate({
        targetUrl: 'https://data.provider.com/item2',
        costUsd: 0.8,
        toolName: 'fetch',
      });
      expect(secondCall.allowed).toBe(true);
      expect(secondCall.remainingHourlyBudgetUsd).toBeCloseTo(0.9);

      // Exceeds hourly budget (0.9 remaining, requesting 1.0)
      const thirdCall = guard.evaluate({
        targetUrl: 'https://data.provider.com/item3',
        costUsd: 1.0,
        toolName: 'fetch',
      });
      expect(thirdCall.allowed).toBe(false);
      expect(thirdCall.reason).toContain('Hourly spend limit');
    });
  });

  describe('Module 2: Deliverable Escrow Engine', () => {
    const keyPair = DeliverableEscrowEngine.generateKeyPair();
    const DeliverableSchema = z.object({
      summary: z.string().min(5),
      sentimentScore: z.number().min(-1).max(1),
      tags: z.array(z.string()),
    });

    it('should release payment and generate signature when schema & SLA match', async () => {
      const validDeliverable = {
        summary: 'Market analysis complete for Q3',
        sentimentScore: 0.85,
        tags: ['finance', 'bullish'],
      };

      const result = await DeliverableEscrowEngine.verifyAndRelease({
        promptId: 'job_4829',
        deliverable: validDeliverable,
        schema: DeliverableSchema,
        maxLatencyMs: 2000,
        actualLatencyMs: 450,
        signingKeyPair: keyPair,
      });

      expect(result.success).toBe(true);
      expect(result.releaseTokenHex).toBeDefined();
      expect(result.auditRecord.passed).toBe(true);
      expect(result.auditRecord.signerPublicKeyHex).toBeDefined();
    });

    it('should reject payment if deliverable schema is invalid', async () => {
      const invalidDeliverable = {
        summary: 'Bad', // too short (< 5 chars)
        sentimentScore: 10, // out of range (-1 to 1)
        tags: 'not-an-array',
      };

      const result = await DeliverableEscrowEngine.verifyAndRelease({
        promptId: 'job_4830',
        deliverable: invalidDeliverable,
        schema: DeliverableSchema,
        maxLatencyMs: 2000,
        actualLatencyMs: 200,
        signingKeyPair: keyPair,
      });

      expect(result.success).toBe(false);
      expect(result.releaseTokenHex).toBeUndefined();
      expect(result.auditRecord.passed).toBe(false);
      expect(result.auditRecord.validationErrors?.length).toBeGreaterThan(0);
    });

    it('should reject payment if deliverable breaches latency SLA', async () => {
      const validDeliverable = {
        summary: 'Valid summary text',
        sentimentScore: 0.5,
        tags: ['test'],
      };

      const result = await DeliverableEscrowEngine.verifyAndRelease({
        promptId: 'job_4831',
        deliverable: validDeliverable,
        schema: DeliverableSchema,
        maxLatencyMs: 500,
        actualLatencyMs: 1200, // SLA breached
        signingKeyPair: keyPair,
      });

      expect(result.success).toBe(false);
      expect(result.auditRecord.validationErrors?.[0]).toContain('Latency SLA breached');
    });
  });

  describe('Module 3: x402 Paywall Middleware', () => {
    const app = new Hono();

    app.use(
      '/paid-data',
      x402Paywall({
        priceEth: '0.001',
        recipientWallet: '0x000000000000000000000000000000000000dEaD',
        mockBypassHeader: 'X-Mock-Bypass',
      })
    );

    app.get('/paid-data', (c) => c.json({ data: 'Confidential Agent Report' }));

    it('should return HTTP 402 with invoice details when no payment header is sent', async () => {
      const res = await app.request('/paid-data');
      expect(res.status).toBe(402);

      const body = await res.json();
      expect(body.status).toBe(402);
      expect(body.amountRequired).toBe('0.001');
      expect(body.recipient).toBe('0x000000000000000000000000000000000000dEaD');
    });

    it('should grant access to route when authentication/payment requirement is cleared', async () => {
      const res = await app.request('/paid-data', {
        headers: {
          'X-Mock-Bypass': 'bypass-payment-authorized',
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data).toBe('Confidential Agent Report');
    });
  });
});
