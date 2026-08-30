<?php

declare(strict_types=1);

namespace App\SpcDemo;

use Symfony\Component\Serializer\Serializer;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialSource;

/**
 * Demo-only credential storage. Persists CredentialRecords (and the user
 * handle that owns them) to a JSON file so the demo survives across HTTP
 * requests with `php -S` without needing a database.
 *
 * Production code MUST use a real persistence layer behind
 * `Webauthn\CredentialRecordRepositoryInterface` instead.
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
     * @return array<string, array{userHandle: string, credentialId: string, source: string}>
     */
    private function readAll(): array
    {
        $raw = (string) file_get_contents($this->file);
        $data = json_decode($raw, true);

        return is_array($data) ? $data : [];
    }

    /**
     * @param array<string, array{userHandle: string, credentialId: string, source: string}> $data
     */
    private function writeAll(array $data): void
    {
        file_put_contents($this->file, json_encode($data, \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR));
    }

    public function save(string $userHandle, CredentialRecord $record): void
    {
        $key = base64_encode($record->publicKeyCredentialId);
        $all = $this->readAll();
        $all[$key] = [
            // userHandle and credentialId are raw bytes — base64-encode for
            // JSON storage so json_encode does not choke on non-UTF-8 input.
            'userHandle' => base64_encode($userHandle),
            'credentialId' => base64_encode($record->publicKeyCredentialId),
            // PublicKeyCredentialSource is the only serializable shape the
            // lib ships with for credentials; its denormalizers base64-encode
            // the byte fields inside, so the resulting string is valid JSON.
            'source' => $this->serializer->serialize($this->toSource($record), 'json'),
        ];
        $this->writeAll($all);
    }

    /**
     * @return string[] base64-encoded credential IDs registered for the user.
     */
    public function credentialIdsForUser(string $userHandle): array
    {
        $needle = base64_encode($userHandle);
        $ids = [];
        foreach ($this->readAll() as $row) {
            if ($row['userHandle'] === $needle) {
                $ids[] = $row['credentialId'];
            }
        }

        return $ids;
    }

    public function findByCredentialId(string $credentialId): ?CredentialRecord
    {
        $key = base64_encode($credentialId);
        $row = $this->readAll()[$key] ?? null;
        if ($row === null) {
            return null;
        }

        $record = $this->serializer->deserialize($row['source'], PublicKeyCredentialSource::class, 'json');
        \assert($record instanceof CredentialRecord);

        return $record;
    }

    public function findUserHandleByCredentialId(string $credentialId): ?string
    {
        $key = base64_encode($credentialId);
        $row = $this->readAll()[$key] ?? null;

        return $row === null ? null : (string) base64_decode($row['userHandle'], true);
    }

    public function updateAfterAssertion(CredentialRecord $record): void
    {
        $key = base64_encode($record->publicKeyCredentialId);
        $all = $this->readAll();
        if (! isset($all[$key])) {
            return;
        }
        $all[$key]['source'] = $this->serializer->serialize($this->toSource($record), 'json');
        $this->writeAll($all);
    }

    private function toSource(CredentialRecord $record): PublicKeyCredentialSource
    {
        return $record instanceof PublicKeyCredentialSource
            ? $record
            : PublicKeyCredentialSource::fromCredentialRecord($record);
    }
}
