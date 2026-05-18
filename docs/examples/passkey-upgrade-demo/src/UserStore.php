<?php

declare(strict_types=1);

namespace App\PasskeyUpgradeDemo;

/**
 * Demo-only user store. Unlike the basic-demo's UserStore, accounts here
 * carry a password hash (PASSWORD_BCRYPT) so the first sign-in factor is a
 * classic password. The passkey-upgrade flow then adds a passkey as an
 * additional, stronger sign-in option on top of the password.
 *
 * The user handle is a 32-byte random blob generated at signup, NOT derived
 * from the username, so that renaming or rotating the username later does
 * not invalidate every passkey. Production code MUST persist users in a real
 * database and treat the user handle as the opaque, immutable account
 * identifier.
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
     * @return array<string, array{userHandle: string, displayName: string, passwordHash: string, createdAt: int}>
     */
    private function readAll(): array
    {
        $raw = (string) file_get_contents($this->file);
        $data = json_decode($raw, true);

        return is_array($data) ? $data : [];
    }

    /**
     * @param array<string, array{userHandle: string, displayName: string, passwordHash: string, createdAt: int}> $data
     */
    private function writeAll(array $data): void
    {
        file_put_contents($this->file, json_encode($data, \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR));
    }

    public function exists(string $username): bool
    {
        return isset($this->readAll()[$username]);
    }

    /**
     * Create a brand-new account. Returns the binary user handle to bind
     * future passkeys against. Throws if the username is already taken.
     */
    public function create(string $username, string $password, string $displayName): string
    {
        $all = $this->readAll();
        if (isset($all[$username])) {
            throw new \RuntimeException('Username already taken.');
        }
        $userHandle = random_bytes(32);
        $all[$username] = [
            'userHandle' => base64_encode($userHandle),
            'displayName' => $displayName === '' ? $username : $displayName,
            'passwordHash' => password_hash($password, \PASSWORD_BCRYPT),
            'createdAt' => time(),
        ];
        $this->writeAll($all);

        return $userHandle;
    }

    /**
     * Verify a password and return the binary user handle on success.
     * Returns null when the username does not exist or the password is wrong.
     */
    public function verifyPassword(string $username, string $password): ?string
    {
        $row = $this->readAll()[$username] ?? null;
        if ($row === null) {
            return null;
        }
        if (! password_verify($password, $row['passwordHash'])) {
            return null;
        }

        return (string) base64_decode($row['userHandle'], true);
    }

    public function findUserHandle(string $username): ?string
    {
        $row = $this->readAll()[$username] ?? null;

        return $row === null ? null : (string) base64_decode($row['userHandle'], true);
    }

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
