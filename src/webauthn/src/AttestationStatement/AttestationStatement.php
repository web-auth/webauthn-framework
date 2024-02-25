<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use JsonSerializable;
use Webauthn\Exception\InvalidDataException;
use Webauthn\TrustPath\TrustPath;
use function array_key_exists;

class AttestationStatement implements JsonSerializable
{
    final public const string TYPE_NONE = 'none';

    final public const string TYPE_BASIC = 'basic';

    final public const string TYPE_SELF = 'self';

    final public const string TYPE_ATTCA = 'attca';

    final public const string TYPE_ANONCA = 'anonca';

    /**
     * @param array<string, mixed> $attStmt
     */
    public function __construct(
        public readonly string $fmt,
        public readonly array $attStmt,
        public readonly string $type,
        public readonly TrustPath $trustPath
    ) {
    }

    public static function create(string $fmt, array $attStmt, string $type, TrustPath $trustPath): self
    {
        return new self($fmt, $attStmt, $type, $trustPath);
    }

    /**
     * @param array<string, mixed> $attStmt
     */
    public static function createNone(string $fmt, array $attStmt, TrustPath $trustPath): self
    {
        return self::create($fmt, $attStmt, self::TYPE_NONE, $trustPath);
    }

    /**
     * @param array<string, mixed> $attStmt
     */
    public static function createBasic(string $fmt, array $attStmt, TrustPath $trustPath): self
    {
        return self::create($fmt, $attStmt, self::TYPE_BASIC, $trustPath);
    }

    /**
     * @param array<string, mixed> $attStmt
     */
    public static function createSelf(string $fmt, array $attStmt, TrustPath $trustPath): self
    {
        return self::create($fmt, $attStmt, self::TYPE_SELF, $trustPath);
    }

    /**
     * @param array<string, mixed> $attStmt
     */
    public static function createAttCA(string $fmt, array $attStmt, TrustPath $trustPath): self
    {
        return self::create($fmt, $attStmt, self::TYPE_ATTCA, $trustPath);
    }

    /**
     * @param array<string, mixed> $attStmt
     */
    public static function createAnonymizationCA(string $fmt, array $attStmt, TrustPath $trustPath): self
    {
        return self::create($fmt, $attStmt, self::TYPE_ANONCA, $trustPath);
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->attStmt);
    }

    public function get(string $key): mixed
    {
        $this->has($key) || throw InvalidDataException::create($this->attStmt, sprintf(
            'The attestation statement has no key "%s".',
            $key
        ));

        return $this->attStmt[$key];
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        return [
            'fmt' => $this->fmt,
            'attStmt' => $this->attStmt,
            'trustPath' => $this->trustPath,
            'type' => $this->type,
        ];
    }
}
