<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\Pure;
use JsonSerializable;
use function Safe\json_decode;

class AuthenticatorSelectionCriteria implements JsonSerializable
{
    public const AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE = null;
    public const AUTHENTICATOR_ATTACHMENT_PLATFORM = 'platform';
    public const AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 'cross-platform';

    public const USER_VERIFICATION_REQUIREMENT_REQUIRED = 'required';
    public const USER_VERIFICATION_REQUIREMENT_PREFERRED = 'preferred';
    public const USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 'discouraged';

    public const RESIDENT_KEY_REQUIREMENT_NONE = null;
    public const RESIDENT_KEY_REQUIREMENT_REQUIRED = 'required';
    public const RESIDENT_KEY_REQUIREMENT_PREFERRED = 'preferred';
    public const RESIDENT_KEY_REQUIREMENT_DISCOURAGED = 'discouraged';

    private ?string $authenticatorAttachment;

    private bool $requireResidentKey;

    private string $userVerification;

    private ?string $residentKey;

    #[Pure]
    public function __construct()
    {
        $this->authenticatorAttachment = null;
        $this->requireResidentKey = false;
        $this->userVerification = self::USER_VERIFICATION_REQUIREMENT_PREFERRED;
        $this->residentKey = self::RESIDENT_KEY_REQUIREMENT_NONE;
    }

    #[Pure]
    public static function create(): self
    {
        return new self();
    }

    public function setAuthenticatorAttachment(?string $authenticatorAttachment): self
    {
        $this->authenticatorAttachment = $authenticatorAttachment;

        return $this;
    }

    public function setRequireResidentKey(bool $requireResidentKey): self
    {
        $this->requireResidentKey = $requireResidentKey;

        return $this;
    }

    public function setUserVerification(string $userVerification): self
    {
        $this->userVerification = $userVerification;

        return $this;
    }

    public function setResidentKey(?string $residentKey): self
    {
        $this->residentKey = $residentKey;

        return $this;
    }

    #[Pure]
    public function getAuthenticatorAttachment(): ?string
    {
        return $this->authenticatorAttachment;
    }

    #[Pure]
    public function isRequireResidentKey(): bool
    {
        return $this->requireResidentKey;
    }

    #[Pure]
    public function getUserVerification(): string
    {
        return $this->userVerification;
    }

    #[Pure]
    public function getResidentKey(): ?string
    {
        return $this->residentKey;
    }

    public static function createFromString(string $data): self
    {
        $data = json_decode($data, true);
        Assertion::isArray($data, 'Invalid data');

        return self::createFromArray($data);
    }

    public static function createFromArray(array $json): self
    {
        return self::create()
            ->setAuthenticatorAttachment($json['authenticatorAttachment'] ?? null)
            ->setRequireResidentKey($json['requireResidentKey'] ?? false)
            ->setUserVerification($json['userVerification'] ?? self::USER_VERIFICATION_REQUIREMENT_PREFERRED)
            ->setResidentKey($json['residentKey'] ?? self::RESIDENT_KEY_REQUIREMENT_NONE)
        ;
    }

    #[Pure]
    #[ArrayShape(['requireResidentKey' => 'bool', 'userVerification' => 'string', 'residentKey' => 'null|string', 'authenticatorAttachment' => 'null|string'])]
    public function jsonSerialize(): array
    {
        $json = [
            'requireResidentKey' => $this->requireResidentKey,
            'userVerification' => $this->userVerification,
        ];
        if (null !== $this->authenticatorAttachment) {
            $json['authenticatorAttachment'] = $this->authenticatorAttachment;
        }
        if (null !== $this->residentKey) {
            $json['residentKey'] = $this->residentKey;
        }

        return $json;
    }
}
