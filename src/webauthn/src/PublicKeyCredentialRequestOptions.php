<?php

declare(strict_types=1);

namespace Webauthn;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Exception\InvalidDataException;
use Webauthn\Util\Base64;
use function array_key_exists;
use function count;
use function in_array;
use const JSON_THROW_ON_ERROR;

final class PublicKeyCredentialRequestOptions extends PublicKeyCredentialOptions
{
    public const USER_VERIFICATION_REQUIREMENT_REQUIRED = 'required';

    public const USER_VERIFICATION_REQUIREMENT_PREFERRED = 'preferred';

    public const USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 'discouraged';

    public ?string $rpId = null;

    /**
     * @var PublicKeyCredentialDescriptor[]
     */
    public array $allowCredentials = [];

    public ?string $userVerification = null;

    public static function create(string $challenge): self
    {
        return new self($challenge);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function setRpId(?string $rpId): self
    {
        $this->rpId = $rpId;

        return $this;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function allowCredential(PublicKeyCredentialDescriptor $allowCredential): self
    {
        $this->allowCredentials[] = $allowCredential;

        return $this;
    }

    /**
     * @deprecated since 4.7.0. No replacement. Please use the property directly.
     */
    public function allowCredentials(PublicKeyCredentialDescriptor ...$allowCredentials): self
    {
        foreach ($allowCredentials as $allowCredential) {
            $this->allowCredentials[] = $allowCredential;
        }

        return $this;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function setUserVerification(?string $userVerification): self
    {
        if ($userVerification === null) {
            $this->rpId = null;

            return $this;
        }
        in_array($userVerification, [
            self::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            self::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            self::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
        ], true) || throw InvalidDataException::create($userVerification, 'Invalid user verification requirement');
        $this->userVerification = $userVerification;

        return $this;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getRpId(): ?string
    {
        return $this->rpId;
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getAllowCredentials(): array
    {
        return $this->allowCredentials;
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getUserVerification(): ?string
    {
        return $this->userVerification;
    }

    public static function createFromString(string $data): static
    {
        $data = json_decode($data, true, flags: JSON_THROW_ON_ERROR);

        return self::createFromArray($data);
    }

    /**
     * @param mixed[] $json
     */
    public static function createFromArray(array $json): static
    {
        array_key_exists('challenge', $json) || throw InvalidDataException::create(
            $json,
            'Invalid input. "challenge" is missing.'
        );

        $allowCredentials = [];
        $allowCredentialList = $json['allowCredentials'] ?? [];
        foreach ($allowCredentialList as $allowCredential) {
            $allowCredentials[] = PublicKeyCredentialDescriptor::createFromArray($allowCredential);
        }

        $challenge = Base64::decode($json['challenge']);

        $object = self::create($challenge);
        $object->rpId = $json['rpId'] ?? null;
        $object->allowCredentials = $allowCredentials;
        $object->userVerification = $json['userVerification'] ?? null;
        $object->timeout = $json['timeout'] ?? null;
        $object->extensions = isset($json['extensions']) ? AuthenticationExtensionsClientInputs::createFromArray(
            $json['extensions']
        ) : AuthenticationExtensionsClientInputs::create();

        return $object;
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $json = [
            'challenge' => Base64UrlSafe::encodeUnpadded($this->challenge),
        ];

        if ($this->rpId !== null) {
            $json['rpId'] = $this->rpId;
        }

        if ($this->userVerification !== null) {
            $json['userVerification'] = $this->userVerification;
        }

        if (count($this->allowCredentials) !== 0) {
            $json['allowCredentials'] = array_map(
                static fn (PublicKeyCredentialDescriptor $object): array => $object->jsonSerialize(),
                $this->allowCredentials
            );
        }

        if ($this->extensions->count() !== 0) {
            $json['extensions'] = $this->extensions->jsonSerialize();
        }

        if ($this->timeout !== null) {
            $json['timeout'] = $this->timeout;
        }

        return $json;
    }
}
