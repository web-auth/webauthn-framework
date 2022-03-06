<?php

declare(strict_types=1);

namespace Webauthn\AttestationStatement;

use function array_key_exists;
use Assert\Assertion;
use JsonSerializable;
use Webauthn\TrustPath\TrustPath;
use Webauthn\TrustPath\TrustPathLoader;

class AttestationStatement implements JsonSerializable
{
    public const TYPE_NONE = 'none';

    public const TYPE_BASIC = 'basic';

    public const TYPE_SELF = 'self';

    public const TYPE_ATTCA = 'attca';

    public const TYPE_ECDAA = 'ecdaa';

    public const TYPE_ANONCA = 'anonca';

    /**
     * @var mixed[]
     */
    private $attStmt;

    /**
     * @param mixed[] $attStmt
     */
    public function __construct(
        private string $fmt,
        array $attStmt,
        private string $type,
        private TrustPath $trustPath
    ) {
        $this->attStmt = $attStmt;
    }

    /**
     * @param mixed[] $attStmt
     */
    public static function createNone(string $fmt, array $attStmt, TrustPath $trustPath): self
    {
        return new self($fmt, $attStmt, self::TYPE_NONE, $trustPath);
    }

    /**
     * @param mixed[] $attStmt
     */
    public static function createBasic(string $fmt, array $attStmt, TrustPath $trustPath): self
    {
        return new self($fmt, $attStmt, self::TYPE_BASIC, $trustPath);
    }

    /**
     * @param mixed[] $attStmt
     */
    public static function createSelf(string $fmt, array $attStmt, TrustPath $trustPath): self
    {
        return new self($fmt, $attStmt, self::TYPE_SELF, $trustPath);
    }

    /**
     * @param mixed[] $attStmt
     */
    public static function createAttCA(string $fmt, array $attStmt, TrustPath $trustPath): self
    {
        return new self($fmt, $attStmt, self::TYPE_ATTCA, $trustPath);
    }

    /**
     * @param mixed[] $attStmt
     */
    public static function createEcdaa(string $fmt, array $attStmt, TrustPath $trustPath): self
    {
        return new self($fmt, $attStmt, self::TYPE_ECDAA, $trustPath);
    }

    public static function createAnonymizationCA(string $fmt, array $attStmt, TrustPath $trustPath): self
    {
        return new self($fmt, $attStmt, self::TYPE_ANONCA, $trustPath);
    }

    public function getFmt(): string
    {
        return $this->fmt;
    }

    /**
     * @return mixed[]
     */
    public function getAttStmt(): array
    {
        return $this->attStmt;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->attStmt);
    }

    public function get(string $key): mixed
    {
        Assertion::true($this->has($key), sprintf('The attestation statement has no key "%s".', $key));

        return $this->attStmt[$key];
    }

    public function getTrustPath(): TrustPath
    {
        return $this->trustPath;
    }

    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @param mixed[] $data
     */
    public static function createFromArray(array $data): self
    {
        foreach (['fmt', 'attStmt', 'trustPath', 'type'] as $key) {
            Assertion::keyExists($data, $key, sprintf('The key "%s" is missing', $key));
        }

        return new self(
            $data['fmt'],
            $data['attStmt'],
            $data['type'],
            TrustPathLoader::loadTrustPath($data['trustPath'])
        );
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        return [
            'fmt' => $this->fmt,
            'attStmt' => $this->attStmt,
            'trustPath' => $this->trustPath->jsonSerialize(),
            'type' => $this->type,
        ];
    }
}
