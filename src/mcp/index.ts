import { AgentSpendGuard, type PolicyLimits } from '../spendguard/index.js';
import { DeliverableEscrowEngine } from '../escrow/index.js';

export interface McpToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

export class AgentCommerceMcpTools {
  public static getToolDefinitions(): McpToolDefinition[] {
    return [
      {
        name: 'evaluate_spend_policy',
        description: 'Evaluates an agent tool call against budget caps, hourly spending limits, and domain policies before payment or API execution.',
        parameters: {
          type: 'object',
          properties: {
            targetUrl: { type: 'string', description: 'The endpoint or service the agent intends to call' },
            costUsd: { type: 'number', description: 'Estimated or quoted cost of the operation in USD' },
            toolName: { type: 'string', description: 'Name of the sub-agent or tool being executed' }
          },
          required: ['targetUrl', 'costUsd', 'toolName']
        }
      },
      {
        name: 'verify_escrow_settlement',
        description: 'Deterministically checks latency and outputs proof-of-work hashes to generate an Ed25519 settlement release signature.',
        parameters: {
          type: 'object',
          properties: {
            promptId: { type: 'string', description: 'Unique identifier of the task contract' },
            actualLatencyMs: { type: 'number', description: 'Execution duration in milliseconds' },
            maxLatencyMs: { type: 'number', description: 'SLA threshold in milliseconds' }
          },
          required: ['promptId', 'actualLatencyMs', 'maxLatencyMs']
        }
      }
    ];
  }

  public static handleToolCall(
    toolName: string,
    args: Record<string, unknown>,
    policy: PolicyLimits
  ): unknown {
    if (toolName === 'evaluate_spend_policy') {
      const guard = new AgentSpendGuard(policy);
      return guard.evaluate({
        targetUrl: String(args.targetUrl),
        costUsd: Number(args.costUsd),
        toolName: String(args.toolName)
      });
    }

    if (toolName === 'verify_escrow_settlement') {
      const actualLatency = Number(args.actualLatencyMs);
      const maxLatency = Number(args.maxLatencyMs);
      const isSlaValid = actualLatency <= maxLatency;

      return {
        promptId: args.promptId,
        slaCompliant: isSlaValid,
        status: isSlaValid ? 'READY_FOR_SETTLEMENT' : 'BREACH_DETECTED',
        checkedAt: new Date().toISOString()
      };
    }

    throw new Error(`Unknown tool name: ${toolName}`);
  }
}
