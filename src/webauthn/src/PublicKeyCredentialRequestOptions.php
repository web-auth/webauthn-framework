<?php

declare(strict_types=1);

namespace Webauthn;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\Exception\InvalidDataException;
use function count;
use function in_array;

final class PublicKeyCredentialRequestOptions extends PublicKeyCredentialOptions
{
    public const null USER_VERIFICATION_REQUIREMENT_DEFAULT = null;

    public const string USER_VERIFICATION_REQUIREMENT_REQUIRED = 'required';

    public const string USER_VERIFICATION_REQUIREMENT_PREFERRED = 'preferred';

    public const string USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 'discouraged';

    public const array USER_VERIFICATION_REQUIREMENTS = [
        self::USER_VERIFICATION_REQUIREMENT_DEFAULT,
        self::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        self::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        self::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
    ];

    /**
     * @param PublicKeyCredentialDescriptor[] $allowCredentials
     * @param null|AuthenticationExtensions|array<array-key, mixed|AuthenticationExtensions> $extensions
     */
    public function __construct(
        string $challenge,
        public null|string $rpId = null,
        public array $allowCredentials = [],
        public null|string $userVerification = null,
        null|int $timeout = null,
        null|array|AuthenticationExtensions $extensions = null,
    ) {
        in_array($userVerification, self::USER_VERIFICATION_REQUIREMENTS, true) || throw InvalidDataException::create(
            $userVerification,
            'Invalid user verification requirement'
        );
        parent::__construct(
            $challenge,
            $timeout,
            $extensions
        );
    }

    /**
     * @param PublicKeyCredentialDescriptor[] $allowCredentials
     * @param positive-int $timeout
     * @param null|AuthenticationExtensions|array<array-key, AuthenticationExtensions> $extensions
     */
    public static function create(
        string $challenge,
        null|string $rpId = null,
        array $allowCredentials = [],
        null|string $userVerification = null,
        null|int $timeout = null,
        null|array|AuthenticationExtensions $extensions = null,
    ): self {
        return new self($challenge, $rpId, $allowCredentials, $userVerification, $timeout, $extensions);
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
            $json['allowCredentials'] = $this->allowCredentials;
        }

        if ($this->extensions->count() !== 0) {
            $json['extensions'] = $this->extensions;
        }

        if ($this->timeout !== null) {
            $json['timeout'] = $this->timeout;
        }

        return $json;
    }
}
