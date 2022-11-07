<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use function count;
use function in_array;
use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Exception\InvalidDataException;
use Webauthn\Util\Base64;

final class PublicKeyCredentialRequestOptions extends PublicKeyCredentialOptions
{
    public const USER_VERIFICATION_REQUIREMENT_REQUIRED = 'required';

    public const USER_VERIFICATION_REQUIREMENT_PREFERRED = 'preferred';

    public const USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 'discouraged';

    private ?string $rpId = null;

    /**
     * @var PublicKeyCredentialDescriptor[]
     */
    private array $allowCredentials = [];

    private ?string $userVerification = null;

    public static function create(string $challenge): self
    {
        return new self($challenge);
    }

    public function setRpId(?string $rpId): self
    {
        $this->rpId = $rpId;

        return $this;
    }

    public function allowCredential(PublicKeyCredentialDescriptor $allowCredential): self
    {
        $this->allowCredentials[] = $allowCredential;

        return $this;
    }

    public function allowCredentials(PublicKeyCredentialDescriptor ...$allowCredentials): self
    {
        foreach ($allowCredentials as $allowCredential) {
            $this->allowCredential($allowCredential);
        }

        return $this;
    }

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

    public function getRpId(): ?string
    {
        return $this->rpId;
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    public function getAllowCredentials(): array
    {
        return $this->allowCredentials;
    }

    public function getUserVerification(): ?string
    {
        return $this->userVerification;
    }

    public static function createFromString(string $data): static
    {
        $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);

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

        return self::create($challenge)
            ->setRpId($json['rpId'] ?? null)
            ->allowCredentials(...$allowCredentials)
            ->setUserVerification($json['userVerification'] ?? null)
            ->setTimeout($json['timeout'] ?? null)
            ->setExtensions(
                isset($json['extensions']) ? AuthenticationExtensionsClientInputs::createFromArray(
                    $json['extensions']
                ) : new AuthenticationExtensionsClientInputs()
            );
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
