# Agent Commerce Kit ⚡

[![Test Suite](https://github.com/mysukriramli/agent-commerce-kit/actions/workflows/test.yml/badge.svg)](https://github.com/YOUR_GITHUB_USERNAME/agent-commerce-kit/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight, zero-overhead developer toolkit powering autonomous machine-to-machine commerce:

1. **Agent Spend-Guard:** Deterministic budget enforcement, single-call caps, and domain whitelisting to prevent runaway agent spend and prompt-injection financial exploits.
2. **Deliverable Escrow Engine:** Schema validation and SLA heuristic checks with Ed25519 settlement release tokens and JSON-LD audit logs.
3. **x402 Paywall Middleware:** Drop-in HTTP `402 Payment Required` route guards for Hono with native on-chain verification on Base Sepolia.

---

## Installation

```bash
npm install agent-commerce-kit
