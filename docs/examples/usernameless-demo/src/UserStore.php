<?php

declare(strict_types=1);

namespace App\UsernamelessDemo;

/**
 * Demo-only user store. Maps usernames to a stable WebAuthn user handle and a
 * human display name.
 *
 * The user handle is the bytes the relying party puts in
 * `PublicKeyCredentialUserEntity.id`. The W3C spec requires that it:
 *
 *  - is a unique, opaque byte string (NOT the username, NOT an email);
 *  - never changes for the lifetime of the account;
 *  - is at most 64 bytes long.
 *
 * In a real application the user handle is typically the binary form of the
 * account's primary key (UUID, ULID, ...). This demo derives it deterministically
 * from the username so the same username always maps to the same handle across
 * fresh starts.
 *
 * Production code MUST persist users in a real database and treat the user
 * handle as the opaque, immutable account identifier.
 */
final class UserStore
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
     * @return array<string, array{userHandle: string, displayName: string, createdAt: int}>
     */
    private function readAll(): array
    {
        $raw = (string) file_get_contents($this->file);
        $data = json_decode($raw, true);

        return is_array($data) ? $data : [];
    }

    /**
     * @param array<string, array{userHandle: string, displayName: string, createdAt: int}> $data
     */
    private function writeAll(array $data): void
    {
        file_put_contents($this->file, json_encode($data, \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR));
    }

    /**
     * Look up an existing user by username, or create a fresh account on first sight.
     * Returns the binary user handle the WebAuthn user entity expects.
     */
    public function findOrCreate(string $username, string $displayName): string
    {
        $all = $this->readAll();
        if (isset($all[$username])) {
            return (string) base64_decode($all[$username]['userHandle'], true);
        }
        $userHandle = random_bytes(32);
        $all[$username] = [
            'userHandle' => base64_encode($userHandle),
            'displayName' => $displayName === '' ? $username : $displayName,
            'createdAt' => time(),
        ];
        $this->writeAll($all);

        return $userHandle;
    }

    /**
     * Returns the binary user handle for a known username, or null if the
     * account has never been seen.
     */
    public function findUserHandle(string $username): ?string
    {
        $row = $this->readAll()[$username] ?? null;

        return $row === null ? null : (string) base64_decode($row['userHandle'], true);
    }

    /**
     * Returns the username bound to a user handle. Used during sign-in to map
     * the bytes the authenticator returned back to a human-readable identity.
     */
    public function findUsernameByHandle(string $userHandle): ?string
    {
        $needle = base64_encode($userHandle);
        foreach ($this->readAll() as $username => $row) {
            if ($row['userHandle'] === $needle) {
                return $username;
            }
        }

        return null;
    }

    public function findDisplayName(string $username): ?string
    {
        return $this->readAll()[$username]['displayName'] ?? null;
    }
}
