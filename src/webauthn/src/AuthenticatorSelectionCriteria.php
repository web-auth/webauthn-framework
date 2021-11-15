<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use const E_USER_DEPRECATED;
use const JSON_THROW_ON_ERROR;
use JsonSerializable;

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

    private ?string $residentKey = null;

    public function __construct(
        ?string $authenticatorAttachment = null,
        ?bool $requireResidentKey = null,
        ?string $userVerification = null,
        ?string $residentKey = null
    ) {
        if ($authenticatorAttachment !== null) {
            @trigger_error(
                'The argument "authenticatorAttachment" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setAuthenticatorAttachment".',
                E_USER_DEPRECATED
            );
        }
        if ($requireResidentKey !== null) {
            @trigger_error(
                'The argument "requireResidentKey" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setRequireResidentKey".',
                E_USER_DEPRECATED
            );
        }
        if ($userVerification !== null) {
            @trigger_error(
                'The argument "userVerification" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setUserVerification".',
                E_USER_DEPRECATED
            );
        }
        if ($residentKey !== null) {
            @trigger_error(
                'The argument "residentKey" is deprecated since version 3.3 and will be removed in 4.0. Please use the method "setResidentKey".',
                E_USER_DEPRECATED
            );
        }
        $this->authenticatorAttachment = $authenticatorAttachment;
        $this->requireResidentKey = $requireResidentKey ?? false;
        $this->userVerification = $userVerification ?? self::USER_VERIFICATION_REQUIREMENT_PREFERRED;
        $this->residentKey = $residentKey ?? self::RESIDENT_KEY_REQUIREMENT_NONE;
    }

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

    public function getAuthenticatorAttachment(): ?string
    {
        return $this->authenticatorAttachment;
    }

    public function isRequireResidentKey(): bool
    {
        return $this->requireResidentKey;
    }

    public function getUserVerification(): string
    {
        return $this->userVerification;
    }

    public function getResidentKey(): ?string
    {
        return $this->residentKey;
    }

    public static function createFromString(string $data): self
    {
        $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
        Assertion::isArray($data, 'Invalid data');

        return self::createFromArray($data);
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        return self::create()
            ->setAuthenticatorAttachment($json['authenticatorAttachment'] ?? null)
            ->setRequireResidentKey($json['requireResidentKey'] ?? false)
            ->setUserVerification($json['userVerification'] ?? self::USER_VERIFICATION_REQUIREMENT_PREFERRED)
            ->setResidentKey($json['residentKey'] ?? self::RESIDENT_KEY_REQUIREMENT_NONE)
        ;
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $json = [
            'requireResidentKey' => $this->requireResidentKey,
            'userVerification' => $this->userVerification,
        ];
        if ($this->authenticatorAttachment !== null) {
            $json['authenticatorAttachment'] = $this->authenticatorAttachment;
        }
        if ($this->residentKey !== null) {
            $json['residentKey'] = $this->residentKey;
        }

        return $json;
    }
}
