<?php

declare(strict_types=1);

namespace App\BasicDemo;

use Symfony\Component\Serializer\Serializer;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;

/**
 * Demo-only credential store. Each row keeps:
 *
 *  - `userHandle`         the binary user handle the credential is bound to
 *                         (base64-encoded for JSON storage);
 *  - `credentialId`       the binary credential ID (base64-encoded);
 *  - `source`             the framework's CredentialRecord serialized to JSON.
 *                         This is the canonical blob to persist after a
 *                         successful attestation. It already contains the
 *                         credential ID, the COSE public key, the signature
 *                         counter, the AAGUID, transports and the backup flags;
 *  - `label`              a human-friendly alias the user can rename;
 *  - `addedAt`            registration timestamp;
 *  - `lastUsedAt`         updated on every successful assertion.
 *
 * Production code MUST replace this with a real implementation of
 * `Webauthn\CredentialRecordRepositoryInterface` (and optionally
 * `Webauthn\CanSaveCredentialRecord` if it owns persistence). Doctrine users
 * can reuse `DoctrineCredentialSourceRepository` from the Symfony bundle as
 * a reference implementation.
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
     * @return array<string, array{userHandle: string, credentialId: string, source: string, label: string, addedAt: int, lastUsedAt: ?int}>
     */
    private function readAll(): array
    {
        $raw = (string) file_get_contents($this->file);
        $data = json_decode($raw, true);

        return is_array($data) ? $data : [];
    }

    /**
     * @param array<string, array{userHandle: string, credentialId: string, source: string, label: string, addedAt: int, lastUsedAt: ?int}> $data
     */
    private function writeAll(array $data): void
    {
        file_put_contents($this->file, json_encode($data, \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR));
    }

    /**
     * Persist a freshly registered credential. Call this right after
     * `AuthenticatorAttestationResponseValidator::check()` returns.
     */
    public function save(string $userHandle, CredentialRecord $record, string $label): void
    {
        $key = base64_encode($record->publicKeyCredentialId);
        $all = $this->readAll();
        $all[$key] = [
            'userHandle' => base64_encode($userHandle),
            'credentialId' => base64_encode($record->publicKeyCredentialId),
            'source' => $this->serializer->serialize($record, 'json'),
            'label' => $label,
            'addedAt' => time(),
            'lastUsedAt' => null,
        ];
        $this->writeAll($all);
    }

    /**
     * Refresh the stored CredentialRecord after a successful assertion. The
     * counter, backup flags and uvInitialized may have been updated in place
     * by the validator, so we re-serialize the whole record.
     */
    public function updateAfterAssertion(CredentialRecord $record): void
    {
        $key = base64_encode($record->publicKeyCredentialId);
        $all = $this->readAll();
        if (! isset($all[$key])) {
            return;
        }
        $all[$key]['source'] = $this->serializer->serialize($record, 'json');
        $all[$key]['lastUsedAt'] = time();
        $this->writeAll($all);
    }

    public function rename(string $credentialId, string $userHandle, string $label): bool
    {
        $key = base64_encode($credentialId);
        $all = $this->readAll();
        if (! isset($all[$key])) {
            return false;
        }
        if ($all[$key]['userHandle'] !== base64_encode($userHandle)) {
            return false;
        }
        $all[$key]['label'] = $label;
        $this->writeAll($all);

        return true;
    }

    public function delete(string $credentialId, string $userHandle): bool
    {
        $key = base64_encode($credentialId);
        $all = $this->readAll();
        if (! isset($all[$key])) {
            return false;
        }
        if ($all[$key]['userHandle'] !== base64_encode($userHandle)) {
            return false;
        }
        unset($all[$key]);
        $this->writeAll($all);

        return true;
    }

    public function findByCredentialId(string $credentialId): ?CredentialRecord
    {
        $key = base64_encode($credentialId);
        $row = $this->readAll()[$key] ?? null;
        if ($row === null) {
            return null;
        }
        $record = $this->serializer->deserialize($row['source'], CredentialRecord::class, 'json');
        \assert($record instanceof CredentialRecord);

        return $record;
    }

    public function findUserHandleByCredentialId(string $credentialId): ?string
    {
        $key = base64_encode($credentialId);
        $row = $this->readAll()[$key] ?? null;

        return $row === null ? null : (string) base64_decode($row['userHandle'], true);
    }

    /**
     * Build the `allowCredentials` list a relying party passes in
     * PublicKeyCredentialRequestOptions to scope the assertion ceremony to a
     * known user.
     *
     * @return PublicKeyCredentialDescriptor[]
     */
    public function allowCredentialsFor(string $userHandle): array
    {
        $needle = base64_encode($userHandle);
        $descriptors = [];
        foreach ($this->readAll() as $row) {
            if ($row['userHandle'] !== $needle) {
                continue;
            }
            $rawId = (string) base64_decode($row['credentialId'], true);
            $descriptors[] = PublicKeyCredentialDescriptor::create('public-key', $rawId);
        }

        return $descriptors;
    }

    /**
     * Build the `excludeCredentials` list a relying party passes in
     * PublicKeyCredentialCreationOptions to prevent registering the same
     * authenticator twice for the same user.
     *
     * @return PublicKeyCredentialDescriptor[]
     */
    public function excludeCredentialsFor(string $userHandle): array
    {
        return $this->allowCredentialsFor($userHandle);
    }

    /**
     * @return list<array{credentialId: string, label: string, addedAt: int, lastUsedAt: ?int, counter: int, aaguid: string, transports: list<string>, backupEligible: ?bool, backupStatus: ?bool}>
     */
    public function listForUser(string $userHandle): array
    {
        $needle = base64_encode($userHandle);
        $rows = [];
        foreach ($this->readAll() as $row) {
            if ($row['userHandle'] !== $needle) {
                continue;
            }
            $record = $this->serializer->deserialize($row['source'], CredentialRecord::class, 'json');
            \assert($record instanceof CredentialRecord);
            $rows[] = [
                'credentialId' => $row['credentialId'],
                'label' => $row['label'],
                'addedAt' => $row['addedAt'],
                'lastUsedAt' => $row['lastUsedAt'],
                'counter' => $record->counter,
                'aaguid' => $record->aaguid->toRfc4122(),
                'transports' => $record->transports,
                'backupEligible' => $record->backupEligible,
                'backupStatus' => $record->backupStatus,
            ];
        }

        return $rows;
    }

    public function countForUser(string $userHandle): int
    {
        return count($this->listForUser($userHandle));
    }
}
