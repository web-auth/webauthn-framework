<?php

declare(strict_types=1);

namespace Webauthn\TokenBinding;

use function array_key_exists;
use Assert\Assertion;
use Webauthn\Util\Base64;

class TokenBinding
{
    final public const TOKEN_BINDING_STATUS_PRESENT = 'present';

    final public const TOKEN_BINDING_STATUS_SUPPORTED = 'supported';

    final public const TOKEN_BINDING_STATUS_NOT_SUPPORTED = 'not-supported';

    private readonly string $status;

    private readonly ?string $id;

    public function __construct(string $status, ?string $id)
    {
        Assertion::false(
            $status === self::TOKEN_BINDING_STATUS_PRESENT && $id === null,
            'The member "id" is required when status is "present"'
        );
        $this->status = $status;
        $this->id = $id;
    }

    /**
     * @param mixed[] $json
     */
    public static function createFormArray(array $json): self
    {
        Assertion::keyExists($json, 'status', 'The member "status" is required');
        $status = $json['status'];
        Assertion::inArray(
            $status,
            self::getSupportedStatus(),
            sprintf(
                'The member "status" is invalid. Supported values are: %s',
                implode(', ', self::getSupportedStatus())
            )
        );
        $id = array_key_exists('id', $json) ? Base64::decodeUrlSafe($json['id']) : null;

        return new self($status, $id);
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function getId(): ?string
    {
        return $this->id;
    }

    /**
     * @return string[]
     */
    private static function getSupportedStatus(): array
    {
        return [
            self::TOKEN_BINDING_STATUS_PRESENT,
            self::TOKEN_BINDING_STATUS_SUPPORTED,
            self::TOKEN_BINDING_STATUS_NOT_SUPPORTED,
        ];
    }
}
