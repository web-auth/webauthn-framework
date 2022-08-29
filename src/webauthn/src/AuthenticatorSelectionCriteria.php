<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use const JSON_THROW_ON_ERROR;
use JsonSerializable;

class AuthenticatorSelectionCriteria implements JsonSerializable
{
    final public const AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE = null;

    final public const AUTHENTICATOR_ATTACHMENT_PLATFORM = 'platform';

    final public const AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 'cross-platform';

    final public const USER_VERIFICATION_REQUIREMENT_REQUIRED = 'required';

    final public const USER_VERIFICATION_REQUIREMENT_PREFERRED = 'preferred';

    final public const USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 'discouraged';

    final public const RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE = null;

    /**
     * @deprecated Please use AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE instead
     */
    final public const RESIDENT_KEY_REQUIREMENT_NONE = null;

    final public const RESIDENT_KEY_REQUIREMENT_REQUIRED = 'required';

    final public const RESIDENT_KEY_REQUIREMENT_PREFERRED = 'preferred';

    final public const RESIDENT_KEY_REQUIREMENT_DISCOURAGED = 'discouraged';

    private ?string $authenticatorAttachment = null;

    /**
     * @deprecated Will be removed in 5.0. Please use residentKey instead
     */
    private bool $requireResidentKey = false;

    private string $userVerification = self::USER_VERIFICATION_REQUIREMENT_PREFERRED;

    private string $residentKey = self::RESIDENT_KEY_REQUIREMENT_PREFERRED;

    public static function create(): self
    {
        return new self();
    }

    public function setAuthenticatorAttachment(?string $authenticatorAttachment): self
    {
        $this->authenticatorAttachment = $authenticatorAttachment;

        return $this;
    }

    /**
     * @deprecated since v4.1. Please use setResidentKey instead
     */
    public function setRequireResidentKey(bool $requireResidentKey): self
    {
        $this->requireResidentKey = $requireResidentKey;
        $this->residentKey = $requireResidentKey ? self::RESIDENT_KEY_REQUIREMENT_REQUIRED : self::RESIDENT_KEY_REQUIREMENT_DISCOURAGED;

        return $this;
    }

    public function setUserVerification(string $userVerification): self
    {
        $this->userVerification = $userVerification;

        return $this;
    }

    public function setResidentKey(string $residentKey): self
    {
        $this->residentKey = $residentKey;
        $this->requireResidentKey = $residentKey === self::RESIDENT_KEY_REQUIREMENT_REQUIRED;

        return $this;
    }

    public function getAuthenticatorAttachment(): ?string
    {
        return $this->authenticatorAttachment;
    }

    /**
     * @deprecated Will be removed in 5.0. Please use getResidentKey() instead
     */
    public function isRequireResidentKey(): bool
    {
        return $this->requireResidentKey;
    }

    public function getUserVerification(): string
    {
        return $this->userVerification;
    }

    public function getResidentKey(): string
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
        $authenticatorAttachment = $json['authenticatorAttachment'] ?? null;
        $requireResidentKey = $json['requireResidentKey'] ?? false;
        $userVerification = $json['userVerification'] ?? self::USER_VERIFICATION_REQUIREMENT_PREFERRED;
        $residentKey = $json['residentKey'] ?? self::RESIDENT_KEY_REQUIREMENT_PREFERRED;

        Assertion::nullOrString($authenticatorAttachment, 'Invalid "authenticatorAttachment" value');
        Assertion::boolean($requireResidentKey, 'Invalid "requireResidentKey" value');
        Assertion::string($userVerification, 'Invalid "userVerification" value');
        Assertion::string($residentKey, 'Invalid "residentKey" value');

        return self::create()
            ->setAuthenticatorAttachment($authenticatorAttachment)
            ->setRequireResidentKey($requireResidentKey)
            ->setUserVerification($userVerification)
            ->setResidentKey($residentKey);
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $json = [
            'requireResidentKey' => $this->requireResidentKey,
            'userVerification' => $this->userVerification,
            // 'residentKey' => $this->residentKey, // TODO: On hold. Waiting for issue clarification. See https://github.com/fido-alliance/conformance-test-tools-resources/issues/676
        ];
        if ($this->authenticatorAttachment !== null) {
            $json['authenticatorAttachment'] = $this->authenticatorAttachment;
        }

        return $json;
    }
}
