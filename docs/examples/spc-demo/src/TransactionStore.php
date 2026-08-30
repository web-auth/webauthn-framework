<?php

declare(strict_types=1);

namespace App\SpcDemo;

/**
 * Demo-only async transaction store. The merchant backend stores the
 * WebAuthn assertion the moment it arrives from the browser (status
 * PENDING) and returns immediately to the user. The actual ACS round-trip
 * to the bank then happens later (lazily on a /status poll, or in a real
 * deployment via a worker / webhook callback).
 *
 * State transitions: PENDING → APPROVED | DECLINED.
 */
final class TransactionStore
{
    public const STATUS_PENDING = 'PENDING';
    public const STATUS_APPROVED = 'APPROVED';
    public const STATUS_DECLINED = 'DECLINED';

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
     * @param array<string, mixed> $assertion
     */
    public function submit(string $transactionId, array $assertion): void
    {
        $all = $this->readAll();
        $all[$transactionId] = [
            'status' => self::STATUS_PENDING,
            'submittedAt' => time(),
            'assertion' => $assertion,
            'bankResponse' => null,
            'error' => null,
        ];
        $this->writeAll($all);
    }

    /**
     * @return array{status: string, submittedAt: int, assertion: array<string, mixed>, bankResponse: array<string, mixed>|null, error: string|null}|null
     */
    public function get(string $transactionId): ?array
    {
        $all = $this->readAll();

        return $all[$transactionId] ?? null;
    }

    /**
     * @param array<string, mixed> $bankResponse
     */
    public function approve(string $transactionId, array $bankResponse): void
    {
        $this->updateStatus($transactionId, self::STATUS_APPROVED, $bankResponse, null);
    }

    public function decline(string $transactionId, string $reason): void
    {
        $this->updateStatus($transactionId, self::STATUS_DECLINED, null, $reason);
    }

    /**
     * @param array<string, mixed>|null $bankResponse
     */
    private function updateStatus(string $transactionId, string $status, ?array $bankResponse, ?string $error): void
    {
        $all = $this->readAll();
        if (! isset($all[$transactionId])) {
            return;
        }
        $all[$transactionId]['status'] = $status;
        $all[$transactionId]['bankResponse'] = $bankResponse;
        $all[$transactionId]['error'] = $error;
        $this->writeAll($all);
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function readAll(): array
    {
        $raw = (string) file_get_contents($this->file);
        $data = json_decode($raw, true);

        return is_array($data) ? $data : [];
    }

    /**
     * @param array<string, array<string, mixed>> $data
     */
    private function writeAll(array $data): void
    {
        file_put_contents($this->file, json_encode($data, \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR));
    }
}
