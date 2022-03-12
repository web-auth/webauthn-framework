<?php

declare(strict_types=1);

namespace Webauthn\TokenBinding;

use function array_key_exists;
use Assert\Assertion;
use Base64Url\Base64Url;
use function Safe\sprintf;

class TokenBinding
{
    public const TOKEN_BINDING_STATUS_PRESENT = 'present';
    public const TOKEN_BINDING_STATUS_SUPPORTED = 'supported';
    public const TOKEN_BINDING_STATUS_NOT_SUPPORTED = 'not-supported';

    private string $status;

    private ?string $id;

    public function __construct(string $status, ?string $id)
    {
        Assertion::false(self::TOKEN_BINDING_STATUS_PRESENT === $status && null === $id, 'The member "id" is required when status is "present"');
        $this->status = $status;
        $this->id = $id;
    }

    public static function createFormArray(array $json): self
    {
        Assertion::keyExists($json, 'status', 'The member "status" is required');
        $status = $json['status'];
        Assertion::inArray(
            $status,
            self::getSupportedStatus(),
            sprintf('The member "status" is invalid. Supported values are: %s', implode(', ', self::getSupportedStatus()))
        );
        $id = array_key_exists('id', $json) ? Base64Url::decode($json['id']) : null;

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
