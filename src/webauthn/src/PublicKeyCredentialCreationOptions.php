<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use function count;
use function in_array;
use function is_array;
use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\Exception\InvalidDataException;
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

    private ?AuthenticatorSelectionCriteria $authenticatorSelection = null;

    private ?string $attestation = null;

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

    public function setAuthenticatorSelection(?AuthenticatorSelectionCriteria $authenticatorSelection): self
    {
        $this->authenticatorSelection = $authenticatorSelection;

        return $this;
    }

    public function setAttestation(string $attestation): self
    {
        in_array($attestation, [
            self::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            self::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
            self::ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
            self::ATTESTATION_CONVEYANCE_PREFERENCE_ENTERPRISE,
        ], true) || throw InvalidDataException::create($attestation, 'Invalid attestation conveyance mode');
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

    public function getAuthenticatorSelection(): ?AuthenticatorSelectionCriteria
    {
        return $this->authenticatorSelection;
    }

    public function getAttestation(): ?string
    {
        return $this->attestation;
    }

    public static function createFromString(string $data): static
    {
        $data = json_decode($data, true, 512, JSON_THROW_ON_ERROR);

        return self::createFromArray($data);
    }

    public static function createFromArray(array $json): static
    {
        array_key_exists('rp', $json) || throw InvalidDataException::create($json, 'Invalid input. "rp" is missing.');
        array_key_exists('pubKeyCredParams', $json) || throw InvalidDataException::create(
            $json,
            'Invalid input. "pubKeyCredParams" is missing.'
        );
        is_array($json['pubKeyCredParams']) || throw InvalidDataException::create(
            $json,
            'Invalid input. "pubKeyCredParams" is not an array.'
        );
        array_key_exists('challenge', $json) || throw InvalidDataException::create(
            $json,
            'Invalid input. "challenge" is missing.'
        );
        array_key_exists('attestation', $json) || throw InvalidDataException::create(
            $json,
            'Invalid input. "attestation" is missing.'
        );
        array_key_exists('user', $json) || throw InvalidDataException::create(
            $json,
            'Invalid input. "user" is missing.'
        );

        $pubKeyCredParams = [];
        foreach ($json['pubKeyCredParams'] as $pubKeyCredParam) {
            if (! is_array($pubKeyCredParam)) {
                continue;
            }
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
                ->setTimeout($json['timeout'] ?? null)
                ->excludeCredentials(...$excludeCredentials)
                ->setAuthenticatorSelection(
                    isset($json['authenticatorSelection']) ? AuthenticatorSelectionCriteria::createFromArray(
                        $json['authenticatorSelection']
                    ) : null
                )
                ->setAttestation($json['attestation'] ?? null)
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
            'rp' => $this->rp->jsonSerialize(),
            'user' => $this->user->jsonSerialize(),
            'challenge' => Base64UrlSafe::encodeUnpadded($this->challenge),
            'pubKeyCredParams' => array_map(
                static fn (PublicKeyCredentialParameters $object): array => $object->jsonSerialize(),
                $this->pubKeyCredParams
            ),
        ];

        if ($this->timeout !== null) {
            $json['timeout'] = $this->timeout;
        }

        if (count($this->excludeCredentials) !== 0) {
            $json['excludeCredentials'] = array_map(
                static fn (PublicKeyCredentialDescriptor $object): array => $object->jsonSerialize(),
                $this->excludeCredentials
            );
        }

        if ($this->authenticatorSelection !== null) {
            $json['authenticatorSelection'] = $this->authenticatorSelection->jsonSerialize();
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
