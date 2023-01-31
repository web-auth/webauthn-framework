<?php

declare(strict_types=1);

namespace Webauthn;

use function is_bool;
use function is_string;
use const JSON_THROW_ON_ERROR;
use JsonSerializable;
use Webauthn\Exception\InvalidDataException;

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

    private null|string $residentKey = self::RESIDENT_KEY_REQUIREMENT_PREFERRED;

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
        //$this->residentKey = $requireResidentKey ? self::RESIDENT_KEY_REQUIREMENT_REQUIRED : self::RESIDENT_KEY_REQUIREMENT_DISCOURAGED;

        return $this;
    }

    public function setUserVerification(string $userVerification): self
    {
        $this->userVerification = $userVerification;

        return $this;
    }

    public function setResidentKey(null|string $residentKey): self
    {
        $this->residentKey = $residentKey;
        //$this->requireResidentKey = $residentKey === self::RESIDENT_KEY_REQUIREMENT_REQUIRED;

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

    public function getResidentKey(): null|string
    {
        return $this->residentKey;
    }

    public static function createFromString(string $data): self
    {
        $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);

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

        $authenticatorAttachment === null || is_string($authenticatorAttachment) || throw InvalidDataException::create(
            $json,
            'Invalid "authenticatorAttachment" value'
        );
        is_bool($requireResidentKey) || throw InvalidDataException::create(
            $json,
            'Invalid "requireResidentKey" value'
        );
        is_string($userVerification) || throw InvalidDataException::create($json, 'Invalid "userVerification" value');
        is_string($residentKey) || throw InvalidDataException::create($json, 'Invalid "residentKey" value');

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
