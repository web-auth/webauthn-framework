<?php

declare(strict_types=1);

namespace Webauthn;

use Assert\Assertion;
use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Util\Base64;

final class PublicKeyCredentialCreationOptions extends PublicKeyCredentialOptions
{
    public const ATTESTATION_CONVEYANCE_PREFERENCE_NONE = 'none';

    public const ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT = 'indirect';

    public const ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT = 'direct';

    public const ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE = 'enterprise';

    /**
     * @var PublicKeyCredentialDescriptor[]
     */
    private array $excludeCredentials = [];

    private AuthenticatorSelectionCriteria $authenticatorSelection;

    private string $attestation;

    /**
     * @param PublicKeyCredentialParameters[] $pubKeyCredParams
     */
    public function __construct(
        private readonly PublicKeyCredentialRpEntity $rp,
        private readonly PublicKeyCredentialUserEntity $user,
        string $challenge,
        private array $pubKeyCredParams
    ) {
        parent::__construct($challenge);
        $this->authenticatorSelection = new AuthenticatorSelectionCriteria();
        $this->attestation = self::ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
    }

    /**
     * @param PublicKeyCredentialParameters[] $pubKeyCredParams
     */
    public static function create(
        PublicKeyCredentialRpEntity $rp,
        PublicKeyCredentialUserEntity $user,
        string $challenge,
        array $pubKeyCredParams
    ): self {
        return new self($rp, $user, $challenge, $pubKeyCredParams);
    }

    public function addPubKeyCredParam(PublicKeyCredentialParameters $pubKeyCredParam): self
    {
        $this->pubKeyCredParams[] = $pubKeyCredParam;

        return $this;
    }

    public function addPubKeyCredParams(PublicKeyCredentialParameters ...$pubKeyCredParams): self
    {
        foreach ($pubKeyCredParams as $pubKeyCredParam) {
            $this->addPubKeyCredParam($pubKeyCredParam);
        }

        return $this;
    }

    public function excludeCredential(PublicKeyCredentialDescriptor $excludeCredential): self
    {
        $this->excludeCredentials[] = $excludeCredential;

        return $this;
    }

    public function excludeCredentials(PublicKeyCredentialDescriptor ...$excludeCredentials): self
    {
        foreach ($excludeCredentials as $excludeCredential) {
            $this->excludeCredential($excludeCredential);
        }

        return $this;
    }

    public function setAuthenticatorSelection(AuthenticatorSelectionCriteria $authenticatorSelection): self
    {
        $this->authenticatorSelection = $authenticatorSelection;

        return $this;
    }

    public function setAttestation(string $attestation): self
    {
        Assertion::inArray($attestation, [
            self::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            self::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            self::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
            self::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE,
        ], 'Invalid attestation conveyance mode');
        $this->attestation = $attestation;

        return $this;
    }

    public function getRp(): PublicKeyCredentialRpEntity
    {
        return $this->rp;
    }

    public function getUser(): PublicKeyCredentialUserEntity
    {
        return $this->user;
    }

    /**
     * @return PublicKeyCredentialParameters[]
     */
    public function getPubKeyCredParams(): array
    {
        return $this->pubKeyCredParams;
    }

    /**
     * @return PublicKeyCredentialDescriptor[]
     */
    public function getExcludeCredentials(): array
    {
        return $this->excludeCredentials;
    }

    public function getAuthenticatorSelection(): AuthenticatorSelectionCriteria
    {
        return $this->authenticatorSelection;
    }

    public function getAttestation(): string
    {
        return $this->attestation;
    }

    public static function createFromString(string $data): static
    {
        $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
        Assertion::isArray($data, 'Invalid data');

        return self::createFromArray($data);
    }

    public static function createFromArray(array $json): static
    {
        Assertion::keyExists($json, 'rp', 'Invalid input. "rp" is missing.');
        Assertion::keyExists($json, 'pubKeyCredParams', 'Invalid input. "pubKeyCredParams" is missing.');
        Assertion::isArray($json['pubKeyCredParams'], 'Invalid input. "pubKeyCredParams" is not an array.');
        Assertion::keyExists($json, 'challenge', 'Invalid input. "challenge" is missing.');
        Assertion::keyExists($json, 'attestation', 'Invalid input. "attestation" is missing.');
        Assertion::keyExists($json, 'user', 'Invalid input. "user" is missing.');
        Assertion::keyExists($json, 'authenticatorSelection', 'Invalid input. "authenticatorSelection" is missing.');

        $pubKeyCredParams = [];
        foreach ($json['pubKeyCredParams'] as $pubKeyCredParam) {
            $pubKeyCredParams[] = PublicKeyCredentialParameters::createFromArray($pubKeyCredParam);
        }
        $excludeCredentials = [];
        if (isset($json['excludeCredentials'])) {
            foreach ($json['excludeCredentials'] as $excludeCredential) {
                $excludeCredentials[] = PublicKeyCredentialDescriptor::createFromArray($excludeCredential);
            }
        }

        $challenge = Base64::decode($json['challenge']);

        return self
            ::create(
                PublicKeyCredentialRpEntity::createFromArray($json['rp']),
                PublicKeyCredentialUserEntity::createFromArray($json['user']),
                $challenge,
                $pubKeyCredParams
            )
                ->excludeCredentials(...$excludeCredentials)
                ->setAuthenticatorSelection(
                    AuthenticatorSelectionCriteria::createFromArray($json['authenticatorSelection'])
                )
                ->setAttestation($json['attestation'])
                ->setTimeout($json['timeout'] ?? null)
                ->setExtensions(
                    isset($json['extensions']) ? AuthenticationExtensionsClientInputs::createFromArray(
                        $json['extensions']
                    ) : new AuthenticationExtensionsClientInputs()
                )
        ;
    }

    /**
     * @return mixed[]
     */
    public function jsonSerialize(): array
    {
        $json = [
            'rp' => $this->rp->jsonSerialize(),
            'pubKeyCredParams' => array_map(
                static fn (PublicKeyCredentialParameters $object): array => $object->jsonSerialize(),
                $this->pubKeyCredParams
            ),
            'challenge' => Base64UrlSafe::encodeUnpadded($this->challenge),
            'attestation' => $this->attestation,
            'user' => $this->user->jsonSerialize(),
            'authenticatorSelection' => $this->authenticatorSelection->jsonSerialize(),
            'excludeCredentials' => array_map(
                static fn (PublicKeyCredentialDescriptor $object): array => $object->jsonSerialize(),
                $this->excludeCredentials
            ),
        ];

        if ($this->extensions->count() !== 0) {
            $json['extensions'] = $this->extensions;
        }

        if ($this->timeout !== null) {
            $json['timeout'] = $this->timeout;
        }

        return $json;
    }
}
