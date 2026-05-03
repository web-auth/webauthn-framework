<?php

declare(strict_types=1);

namespace App\ExtensionsDemo;

use Symfony\Component\Serializer\Serializer;
use Webauthn\CredentialRecord;

/**
 * Demo-only credential store. Persists CredentialRecords plus the inputs that
 * were used at registration time (the requested credProtect policy and the
 * credBlob payload, both echoed back during the assertion page so users can
 * see the round-trip).
 *
 * Production code MUST use a real persistence layer behind
 * `Webauthn\CredentialRecordRepositoryInterface`.
 */
final class CredentialStore
{
    public function __construct(
        private readonly string $file,
        private readonly Serializer $serializer,
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
     * @return array<string, array{userHandle: string, credentialId: string, source: string, requestedCredProtect: ?string, credBlob: string, registrationOutputs: array<string, mixed>}>
     */
    private function readAll(): array
    {
        $raw = (string) file_get_contents($this->file);
        $data = json_decode($raw, true);
        if (! is_array($data)) {
            return [];
        }
        return $data;
    }

    /**
     * @param array<string, array{userHandle: string, credentialId: string, source: string, requestedCredProtect: ?string, credBlob: string, registrationOutputs: array<string, mixed>}> $data
     */
    private function writeAll(array $data): void
    {
        file_put_contents($this->file, json_encode($data, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES));
    }

    /**
     * @param array<string, mixed> $registrationOutputs
     */
    public function save(
        CredentialRecord $record,
        string $credIdB64,
        string $userHandle,
        ?string $requestedCredProtect,
        string $credBlob,
        array $registrationOutputs,
    ): void {
        $data = $this->readAll();
        $data[$credIdB64] = [
            'userHandle' => $userHandle,
            'credentialId' => $credIdB64,
            'source' => $this->serializer->serialize($record, 'json'),
            'requestedCredProtect' => $requestedCredProtect,
            'credBlob' => $credBlob,
            'registrationOutputs' => $registrationOutputs,
        ];
        $this->writeAll($data);
    }

    public function findByCredentialId(string $credentialId): ?CredentialRecord
    {
        $data = $this->readAll();
        foreach ($data as $row) {
            if (base64_decode($row['credentialId'], true) === $credentialId) {
                return $this->serializer->deserialize($row['source'], CredentialRecord::class, 'json');
            }
        }
        return null;
    }

    /**
     * @return array<string, array{userHandle: string, credentialId: string, source: string, requestedCredProtect: ?string, credBlob: string, registrationOutputs: array<string, mixed>}>
     */
    public function all(): array
    {
        return $this->readAll();
    }

    public function update(CredentialRecord $record): void
    {
        $data = $this->readAll();
        $credIdB64 = base64_encode($record->publicKeyCredentialId);
        if (! isset($data[$credIdB64])) {
            return;
        }
        $data[$credIdB64]['source'] = $this->serializer->serialize($record, 'json');
        $this->writeAll($data);
    }
}
