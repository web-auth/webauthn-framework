<?php

declare(strict_types=1);

namespace Webauthn;

use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\Exception\InvalidDataException;
use function count;
use function in_array;

final class PublicKeyCredentialCreationOptions extends PublicKeyCredentialOptions
{
    public const null ATTESTATION_CONVEYANCE_PREFERENCE_DEFAULT = null;

    public const string ATTESTATION_CONVEYANCE_PREFERENCE_NONE = 'none';

    public const string ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT = 'indirect';

    public const string ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT = 'direct';

    public const string ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE = 'enterprise';

    public const array ATTESTATION_CONVEYANCE_PREFERENCES = [
        self::ATTESTATION_CONVEYANCE_PREFERENCE_DEFAULT,
        self::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        self::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
        self::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        self::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE,
    ];

    /**
     * @private
     * @param PublicKeyCredentialParameters[] $pubKeyCredParams
     * @param PublicKeyCredentialDescriptor[] $excludeCredentials
     * @param null|positive-int $timeout
     */
    public function __construct(
        public readonly PublicKeyCredentialRpEntity $rp,
        public readonly PublicKeyCredentialUserEntity $user,
        string $challenge,
        public array $pubKeyCredParams = [],
        public null|AuthenticatorSelectionCriteria $authenticatorSelection = null,
        public null|string $attestation = null,
        public array $excludeCredentials = [],
        null|int $timeout = null,
        null|AuthenticationExtensions $extensions = null,
    ) {
        foreach ($pubKeyCredParams as $pubKeyCredParam) {
            $pubKeyCredParam instanceof PublicKeyCredentialParameters || throw new InvalidArgumentException(
                'Invalid type for $pubKeyCredParams'
            );
        }
        foreach ($excludeCredentials as $excludeCredential) {
            $excludeCredential instanceof PublicKeyCredentialDescriptor || throw new InvalidArgumentException(
                'Invalid type for $excludeCredentials'
            );
        }
        in_array($attestation, self::ATTESTATION_CONVEYANCE_PREFERENCES, true) || throw InvalidDataException::create(
            $attestation,
            'Invalid attestation conveyance mode'
        );

        parent::__construct($challenge, $timeout, $extensions);
    }

    /**
     * @param PublicKeyCredentialParameters[] $pubKeyCredParams
     * @param PublicKeyCredentialDescriptor[] $excludeCredentials
     * @param null|positive-int $timeout
     */
    public static function create(
        PublicKeyCredentialRpEntity $rp,
        PublicKeyCredentialUserEntity $user,
        string $challenge,
        array $pubKeyCredParams = [],
        null|AuthenticatorSelectionCriteria $authenticatorSelection = null,
        null|string $attestation = null,
        array $excludeCredentials = [],
        null|int $timeout = null,
        null|AuthenticationExtensions $extensions = null,
    ): self {
        return new self(
            $rp,
            $user,
            $challenge,
            $pubKeyCredParams,
            $authenticatorSelection,
            $attestation,
            $excludeCredentials,
            $timeout,
            $extensions
        );
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $json = [
            'rp' => $this->rp,
            'user' => $this->user,
            'challenge' => Base64UrlSafe::encodeUnpadded($this->challenge),
            'pubKeyCredParams' => $this->pubKeyCredParams,
        ];

        if ($this->timeout !== null) {
            $json['timeout'] = $this->timeout;
        }

        if (count($this->excludeCredentials) !== 0) {
            $json['excludeCredentials'] = $this->excludeCredentials;
        }

        if ($this->authenticatorSelection !== null) {
            $json['authenticatorSelection'] = $this->authenticatorSelection;
        }

        if ($this->attestation !== null) {
            $json['attestation'] = $this->attestation;
        }

        if ($this->extensions->count() !== 0) {
            $json['extensions'] = $this->extensions;
        }

        return $json;
    }
}
