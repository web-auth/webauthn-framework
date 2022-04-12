<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use const JSON_THROW_ON_ERROR;
use JsonSerializable;

class AuthenticatorSelectionCriteria implements JsonSerializable
{
    public final const AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE = null;

    public final const AUTHENTICATOR_ATTACHMENT_PLATFORM = 'platform';

    public final const AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 'cross-platform';

    public final const USER_VERIFICATION_REQUIREMENT_REQUIRED = 'required';

    public final const USER_VERIFICATION_REQUIREMENT_PREFERRED = 'preferred';

    public final const USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 'discouraged';

    public final const RESIDENT_KEY_REQUIREMENT_NONE = null;

    public final const RESIDENT_KEY_REQUIREMENT_REQUIRED = 'required';

    public final const RESIDENT_KEY_REQUIREMENT_PREFERRED = 'preferred';

    public final const RESIDENT_KEY_REQUIREMENT_DISCOURAGED = 'discouraged';

    private ?string $authenticatorAttachment = null;

    private bool $requireResidentKey;

    private string $userVerification;

    private ?string $residentKey;

    public function __construct()
    {
        $this->requireResidentKey = false;
        $this->userVerification = self::USER_VERIFICATION_REQUIREMENT_PREFERRED;
        $this->residentKey = self::RESIDENT_KEY_REQUIREMENT_NONE;
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
