<?php

declare(strict_types=1);

namespace Webauthn;

use InvalidArgumentException;
use JsonSerializable;
use Webauthn\Exception\InvalidDataException;
use function in_array;
use function is_bool;
use function is_string;
use const JSON_THROW_ON_ERROR;

class AuthenticatorSelectionCriteria implements JsonSerializable
{
    final public const AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE = null;

    final public const AUTHENTICATOR_ATTACHMENT_PLATFORM = 'platform';

    final public const AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 'cross-platform';

    final public const AUTHENTICATOR_ATTACHMENTS = [
        self::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
        self::AUTHENTICATOR_ATTACHMENT_PLATFORM,
        self::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
    ];

    final public const USER_VERIFICATION_REQUIREMENT_REQUIRED = 'required';

    final public const USER_VERIFICATION_REQUIREMENT_PREFERRED = 'preferred';

    final public const USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 'discouraged';

    final public const USER_VERIFICATION_REQUIREMENTS = [
        self::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        self::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        self::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
    ];

    final public const RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE = null;

    /**
     * @deprecated Please use AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE instead
     */
    final public const RESIDENT_KEY_REQUIREMENT_NONE = null;

    final public const RESIDENT_KEY_REQUIREMENT_REQUIRED = 'required';

    final public const RESIDENT_KEY_REQUIREMENT_PREFERRED = 'preferred';

    final public const RESIDENT_KEY_REQUIREMENT_DISCOURAGED = 'discouraged';

    final public const RESIDENT_KEY_REQUIREMENTS = [
        self::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE,
        self::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        self::RESIDENT_KEY_REQUIREMENT_PREFERRED,
        self::RESIDENT_KEY_REQUIREMENT_DISCOURAGED,
    ];

    public function __construct(
        /** @readonly  */
        public null|string $authenticatorAttachment = null,
        /** @readonly  */
        public string $userVerification = self::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        /** @readonly  */
        public null|string $residentKey = self::RESIDENT_KEY_REQUIREMENT_PREFERRED,
        /** @deprecated Will be removed in 5.0. Please use residentKey instead**/
        public null|bool $requireResidentKey = false,
    ) {
        in_array($authenticatorAttachment, self::AUTHENTICATOR_ATTACHMENTS, true) || throw new InvalidArgumentException(
            'Invalid authenticator attachment'
        );
        in_array($userVerification, self::USER_VERIFICATION_REQUIREMENTS, true) || throw new InvalidArgumentException(
            'Invalid user verification'
        );
        in_array($residentKey, self::RESIDENT_KEY_REQUIREMENTS, true) || throw new InvalidArgumentException(
            'Invalid resident key'
        );

        $this->requireResidentKey = $requireResidentKey ?? $residentKey === self::RESIDENT_KEY_REQUIREMENT_REQUIRED;
        $requireResidentKey = $requireResidentKey === true ? self::RESIDENT_KEY_REQUIREMENT_REQUIRED : self::RESIDENT_KEY_REQUIREMENT_PREFERRED;
        $this->residentKey = $residentKey ?? $requireResidentKey;
    }

    public static function create(
        ?string $authenticatorAttachment = null,
        string $userVerification = self::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        null|string $residentKey = self::RESIDENT_KEY_REQUIREMENT_PREFERRED,
        null|bool $requireResidentKey = false
    ): self {
        return new self($authenticatorAttachment, $userVerification, $residentKey, $requireResidentKey);
    }

    /**
     * @deprecated since 4.7.0. Please use the {self::create} instead.
     */
    public function setAuthenticatorAttachment(?string $authenticatorAttachment): self
    {
        $this->authenticatorAttachment = $authenticatorAttachment;

        return $this;
    }

    /**
     * @deprecated since v4.1. Please use the {self::create} instead.
     */
    public function setRequireResidentKey(bool $requireResidentKey): self
    {
        $this->requireResidentKey = $requireResidentKey;
        if ($requireResidentKey === true) {
            $this->residentKey = self::RESIDENT_KEY_REQUIREMENT_REQUIRED;
        }

        return $this;
    }

    /**
     * @deprecated since 4.7.0. Please use the {self::create} instead.
     */
    public function setUserVerification(string $userVerification): self
    {
        $this->userVerification = $userVerification;

        return $this;
    }

    /**
     * @deprecated since 4.7.0. Please use the {self::create} instead.
     */
    public function setResidentKey(null|string $residentKey): self
    {
        $this->residentKey = $residentKey;
        $this->requireResidentKey = $residentKey === self::RESIDENT_KEY_REQUIREMENT_REQUIRED;

        return $this;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getAuthenticatorAttachment(): ?string
    {
        return $this->authenticatorAttachment;
    }

    /**
     * @deprecated Will be removed in 5.0. Please use the property directly.
     */
    public function isRequireResidentKey(): bool
    {
        return $this->requireResidentKey;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getUserVerification(): string
    {
        return $this->userVerification;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getResidentKey(): null|string
    {
        return $this->residentKey;
    }

    public static function createFromString(string $data): self
    {
        $data = json_decode($data, true, flags: JSON_THROW_ON_ERROR);

        return self::createFromArray($data);
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): self
    {
        $authenticatorAttachment = $json['authenticatorAttachment'] ?? null;
        $requireResidentKey = $json['requireResidentKey'] ?? null;
        $userVerification = $json['userVerification'] ?? self::USER_VERIFICATION_REQUIREMENT_PREFERRED;
        $residentKey = $json['residentKey'] ?? null;

        $authenticatorAttachment === null || is_string($authenticatorAttachment) || throw InvalidDataException::create(
            $json,
            'Invalid "authenticatorAttachment" value'
        );
        ($requireResidentKey === null || is_bool($requireResidentKey)) || throw InvalidDataException::create(
            $json,
            'Invalid "requireResidentKey" value'
        );
        is_string($userVerification) || throw InvalidDataException::create($json, 'Invalid "userVerification" value');
        ($residentKey === null || is_string($residentKey)) || throw InvalidDataException::create(
            $json,
            'Invalid "residentKey" value'
        );

        return self::create(
            $authenticatorAttachment ?? null,
            $userVerification,
            $residentKey,
            $requireResidentKey,
        );
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $json = [
            'requireResidentKey' => $this->requireResidentKey,
            'userVerification' => $this->userVerification,
            'residentKey' => $this->residentKey,
        ];
        if ($this->authenticatorAttachment !== null) {
            $json['authenticatorAttachment'] = $this->authenticatorAttachment;
        }

        return $json;
    }
}
