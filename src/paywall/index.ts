import { createMiddleware } from 'hono/factory';
import { createPublicClient, http, parseEther, isAddress, type Hash } from 'viem';
import { baseSepolia } from 'viem/chains';

export interface X402PaywallOptions {
  priceEth: string;
  recipientWallet: `0x${string}`;
  rpcUrl?: string;
  mockBypassHeader?: string;
}

export function x402Paywall(options: X402PaywallOptions) {
  if (!isAddress(options.recipientWallet, { strict: false })) {
    throw new Error(`Invalid recipient wallet address: ${options.recipientWallet}`);
  }

  const client = createPublicClient({
    chain: baseSepolia,
    transport: http(options.rpcUrl || 'https://sepolia.base.org'),
  });

  const requiredWei = parseEther(options.priceEth);

  return createMiddleware(async (c, next) => {
    // Development bypass option for test assertion
    if (
      options.mockBypassHeader &&
      c.req.header(options.mockBypassHeader) === 'bypass-payment-authorized'
    ) {
      await next();
      return;
    }

    const txHash = c.req.header('X-402-Payment-Tx') as Hash | undefined;

    // If no payment header is attached, respond with HTTP 402 Payment Required
    if (!txHash) {
      c.header(
        'WWW-Authenticate',
        `X402 network="base-sepolia", amount="${options.priceEth}", recipient="${options.recipientWallet}"`
      );
      return c.json(
        {
          error: 'Payment Required',
          status: 402,
          currency: 'ETH',
          network: 'base-sepolia',
          amountRequired: options.priceEth,
          recipient: options.recipientWallet,
          instruction: 'Execute transaction on Base Sepolia and attach hash to header: X-402-Payment-Tx',
        },
        402
      );
    }

    // Verify on-chain transaction
    try {
      const receipt = await client.getTransactionReceipt({ hash: txHash });
      const tx = await client.getTransaction({ hash: txHash });

      if (receipt.status !== 'success') {
        return c.json({ error: 'Payment transaction failed on-chain', status: 400 }, 400);
      }

      if (tx.to?.toLowerCase() !== options.recipientWallet.toLowerCase()) {
        return c.json(
          {
            error: 'Payment was sent to incorrect address',
            expected: options.recipientWallet,
            actual: tx.to,
          },
          403
        );
      }

      if (tx.value < requiredWei) {
        return c.json(
          {
            error: 'Insufficient payment sent',
            expectedWei: requiredWei.toString(),
            actualWei: tx.value.toString(),
          },
          402
        );
      }

      // Payment verified; forward execution to the protected route
      await next();
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown RPC error';
      return c.json(
        {
          error: 'Payment verification failed or transaction not found',
          details: errorMessage,
        },
        402
      );
    }
  });
}
