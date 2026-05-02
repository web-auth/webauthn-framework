<?php

declare(strict_types=1);

namespace App\PrfDemo;

use Symfony\Component\Serializer\Serializer;
use Webauthn\CredentialRecord;

/**
 * Demo-only credential + vault storage. Persists CredentialRecords plus a list of
 * client-encrypted vault items (ciphertext, IV, label) to a JSON file so the demo
 * survives across HTTP requests with `php -S` without needing a database.
 *
 * Each credential owns its PRF salt and an array of `items`. Items are opaque to
 * the server — only the browser can decrypt them.
 *
 * Production code MUST use a real persistence layer behind
 * `Webauthn\CredentialRecordRepositoryInterface` and store the encrypted vault
 * in its own table.
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
     * @return array<string, array{userHandle: string, credentialId: string, source: string, prfSalt: string, prfSalt2: string, items: list<array{id: string, label: string, ciphertext: string, iv: string, mac: string, createdAt: int}>}>
     */
    private function readAll(): array
    {
        $raw = (string) file_get_contents($this->file);
        $data = json_decode($raw, true);
        if (! is_array($data)) {
            return [];
        }
        // Backfill missing fields for rows written by an older version of the demo so
        // the typed array shape stays consistent across reads.
        foreach ($data as $key => $row) {
            if (! isset($row['items']) || ! is_array($row['items'])) {
                $data[$key]['items'] = [];
            }
            if (! isset($row['prfSalt2'])) {
                $data[$key]['prfSalt2'] = '';
            }
            foreach ($data[$key]['items'] as $i => $item) {
                if (! isset($item['mac'])) {
                    $data[$key]['items'][$i]['mac'] = '';
                }
            }
        }

        return $data;
    }

    /**
     * @param array<string, array{userHandle: string, credentialId: string, source: string, prfSalt: string, prfSalt2: string, items: list<array{id: string, label: string, ciphertext: string, iv: string, mac: string, createdAt: int}>}> $data
     */
    private function writeAll(array $data): void
    {
        file_put_contents($this->file, json_encode($data, \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR));
    }

    /**
     * Store the freshly registered credential alongside the per-credential PRF salts
     * the relying party will re-issue at every authentication. The salts are part of
     * the encryption derivation but they are not the secret — only the PRF *output*
     * computed by the authenticator is — so storing them in plaintext is fine.
     *
     * Two salts are persisted to demonstrate the full PRF input shape: `first` feeds
     * the AES-GCM data key, `second` is available for any independent derivation
     * (HMAC over labels, secondary key, …). The browser receives both at every
     * ceremony so it can recompute both outputs in a single authenticator call.
     */
    public function save(string $userHandle, CredentialRecord $record, string $prfSalt, string $prfSalt2): void
    {
        $key = base64_encode($record->publicKeyCredentialId);
        $all = $this->readAll();
        $all[$key] = [
            'userHandle' => base64_encode($userHandle),
            'credentialId' => base64_encode($record->publicKeyCredentialId),
            'source' => $this->serializer->serialize($record, 'json'),
            'prfSalt' => base64_encode($prfSalt),
            'prfSalt2' => base64_encode($prfSalt2),
            'items' => [],
        ];
        $this->writeAll($all);
    }

    /**
     * Append a vault item (ciphertext + IV + label HMAC, all computed by the browser) to
     * the credential. The HMAC is opaque to the server: it lets the page detect, after
     * a future unlock, that the server (or a tamperer) silently changed the label or
     * the ciphertext bytes.
     *
     * Returns the generated item id so the page can address it.
     */
    public function appendItem(string $credentialId, string $label, string $ciphertextB64Url, string $ivB64Url, string $macB64Url): string
    {
        $key = base64_encode($credentialId);
        $all = $this->readAll();
        if (! isset($all[$key])) {
            throw new \RuntimeException('Unknown credential.');
        }
        $id = bin2hex(random_bytes(8));
        $all[$key]['items'][] = [
            'id' => $id,
            'label' => $label,
            'ciphertext' => $ciphertextB64Url,
            'iv' => $ivB64Url,
            'mac' => $macB64Url,
            'createdAt' => time(),
        ];
        $this->writeAll($all);

        return $id;
    }

    public function deleteItem(string $credentialId, string $itemId): void
    {
        $key = base64_encode($credentialId);
        $all = $this->readAll();
        if (! isset($all[$key])) {
            return;
        }
        $all[$key]['items'] = array_values(array_filter(
            $all[$key]['items'],
            static fn (array $item): bool => $item['id'] !== $itemId,
        ));
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

    /**
     * @return array{record: CredentialRecord, prfSalt: string, prfSalt2: string, items: list<array{id: string, label: string, ciphertext: string, iv: string, mac: string, createdAt: int}>}|null
     */
    public function findByCredentialId(string $credentialId): ?array
    {
        $key = base64_encode($credentialId);
        $row = $this->readAll()[$key] ?? null;
        if ($row === null) {
            return null;
        }

        $record = $this->serializer->deserialize($row['source'], CredentialRecord::class, 'json');

        return [
            'record' => $record,
            'prfSalt' => (string) base64_decode($row['prfSalt'], true),
            'prfSalt2' => $row['prfSalt2'] === '' ? '' : (string) base64_decode($row['prfSalt2'], true),
            'items' => $row['items'],
        ];
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
        $all[$key]['source'] = $this->serializer->serialize($record, 'json');
        $this->writeAll($all);
    }
}
