<?php

declare(strict_types=1);

namespace App\SpcDemo;

/**
 * Demo-only transient store for in-flight SPC challenges, keyed by the
 * base64url-encoded challenge bytes. Persists to a JSON file so the bank
 * server can recover the request context (transactionId, userHandle and
 * the original PublicKeyCredentialRequestOptions) when the merchant POSTs
 * the assertion back cross-origin — no PHP session, no cookies.
 *
 * Production code would persist this in a TTL'd cache (Redis, Memcached)
 * or a row in your orders table.
 */
final class ChallengeStore
{
    public function __construct(
        private readonly string $file,
    ) {
        $dir = dirname($this->file);
        if (! is_dir($dir)) {
            mkdir($dir, 0o755, true);
        }
        if (! file_exists($this->file)) {
            file_put_contents($this->file, '[]');
        }
    }

    /**
     * @param array{transactionId: string, userHandle: string, requestOptions: string} $context
     */
    public function put(string $challengeKey, array $context): void
    {
        $all = $this->readAll();
        $all[$challengeKey] = [
            'transactionId' => $context['transactionId'],
            // userHandle is raw bytes — base64-encode for valid JSON.
            'userHandle' => base64_encode($context['userHandle']),
            'requestOptions' => $context['requestOptions'],
        ];
        $this->writeAll($all);
    }

    /**
     * @return array{transactionId: string, userHandle: string, requestOptions: string}|null
     */
    public function pop(string $challengeKey): ?array
    {
        $all = $this->readAll();
        if (! isset($all[$challengeKey])) {
            return null;
        }
        $row = $all[$challengeKey];
        unset($all[$challengeKey]);
        $this->writeAll($all);

        return [
            'transactionId' => $row['transactionId'],
            'userHandle' => (string) base64_decode($row['userHandle'], true),
            'requestOptions' => $row['requestOptions'],
        ];
    }

    /**
     * @return array<string, array{transactionId: string, userHandle: string, requestOptions: string}>
     */
    private function readAll(): array
    {
        $raw = (string) file_get_contents($this->file);
        $data = json_decode($raw, true);

        return is_array($data) ? $data : [];
    }

    /**
     * @param array<string, array{transactionId: string, userHandle: string, requestOptions: string}> $data
     */
    private function writeAll(array $data): void
    {
        file_put_contents($this->file, json_encode($data, \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR));
    }
}
