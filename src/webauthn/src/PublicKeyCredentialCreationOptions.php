<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

use Assert\Assertion;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;

class PublicKeyCredentialCreationOptions implements \JsonSerializable
{
    public const ATTESTATION_CONVEYANCE_PREFERENCE_NONE = 'none';
    public const ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT = 'indirect';
    public const ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT = 'direct';

    /**
     * @var PublicKeyCredentialRpEntity
     */
    private $rp;

    /**
     * @var PublicKeyCredentialUserEntity
     */
    private $user;

    /**
     * @var string
     */
    private $challenge;

    /**
     * @var PublicKeyCredentialParameters[]
     */
    private $pubKeyCredParams;

    /**
     * @var int|null
     */
    private $timeout;

    /**
     * @var PublicKeyCredentialDescriptor[]
     */
    private $excludeCredentials;

    /**
     * @var AuthenticatorSelectionCriteria
     */
    private $authenticatorSelection;

    /**
     * @var string
     */
    private $attestation;

    /**
     * @var AuthenticationExtensionsClientInputs
     */
    private $extensions;

    /**
     * PublicKeyCredentialCreationOptions constructor.
     *
     * @param PublicKeyCredentialParameters[] $pubKeyCredParams
     * @param PublicKeyCredentialDescriptor[] $excludeCredentials
     */
    public function __construct(PublicKeyCredentialRpEntity $rp, PublicKeyCredentialUserEntity $user, string $challenge, array $pubKeyCredParams, ?int $timeout, array $excludeCredentials, AuthenticatorSelectionCriteria $authenticatorSelection, string $attestation, ?AuthenticationExtensionsClientInputs $extensions)
    {
        $this->rp = $rp;
        $this->user = $user;
        $this->challenge = $challenge;
        $this->pubKeyCredParams = array_values($pubKeyCredParams);
        $this->timeout = $timeout;
        $this->excludeCredentials = array_values($excludeCredentials);
        $this->authenticatorSelection = $authenticatorSelection;
        $this->attestation = $attestation;
        $this->extensions = $extensions ?? new AuthenticationExtensionsClientInputs();
    }

    public function getRp(): PublicKeyCredentialRpEntity
    {
        return $this->rp;
    }

    public function getUser(): PublicKeyCredentialUserEntity
    {
        return $this->user;
    }

    public function getChallenge(): string
    {
        return $this->challenge;
    }

    /**
     * @return PublicKeyCredentialParameters[]
     */
    public function getPubKeyCredParams(): array
    {
        return $this->pubKeyCredParams;
    }

    public function getTimeout(): ?int
    {
        return $this->timeout;
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

    public function getExtensions(): AuthenticationExtensionsClientInputs
    {
        return $this->extensions;
    }

    public static function createFromJson(array $json): self
    {
        Assertion::keyExists($json, 'rp', 'Invalid input.');
        Assertion::keyExists($json, 'pubKeyCredParams', 'Invalid input.');
        Assertion::isArray($json['pubKeyCredParams'], 'Invalid input.');
        Assertion::keyExists($json, 'challenge', 'Invalid input.');
        Assertion::keyExists($json, 'attestation', 'Invalid input.');
        Assertion::keyExists($json, 'user', 'Invalid input.');
        Assertion::keyExists($json, 'authenticatorSelection', 'Invalid input.');

        $pubKeyCredParams = [];
        foreach ($json['pubKeyCredParams'] as $pubKeyCredParam) {
            $pubKeyCredParams[] = PublicKeyCredentialParameters::createFromJson($pubKeyCredParam);
        }
        $excludeCredentials = [];
        if (isset($json['excludeCredentials'])) {
            foreach ($json['excludeCredentials'] as $excludeCredential) {
                $excludeCredentials[] = PublicKeyCredentialDescriptor::createFromJson($excludeCredential);
            }
        }

        return new self(
            PublicKeyCredentialRpEntity::createFromJson($json['rp']),
            PublicKeyCredentialUserEntity::createFromJson($json['user']),
            \Safe\base64_decode($json['challenge'], true),
            $pubKeyCredParams,
            $json['timeout'] ?? null,
            $excludeCredentials,
            AuthenticatorSelectionCriteria::createFromJson($json['authenticatorSelection']),
            $json['attestation'],
            isset($json['extensions']) ? AuthenticationExtensionsClientInputs::createFromJson($json['extensions']) : new AuthenticationExtensionsClientInputs()
        );
    }

    public function jsonSerialize(): array
    {
        $json = [
            'rp' => $this->rp,
            'pubKeyCredParams' => $this->pubKeyCredParams,
            'challenge' => base64_encode($this->challenge),
            'attestation' => $this->attestation,
            'user' => $this->user,
            'authenticatorSelection' => $this->authenticatorSelection,
        ];

        if (0 !== \count($this->excludeCredentials)) {
            $json['excludeCredentials'] = $this->excludeCredentials;
        }

        if (0 !== $this->extensions->count()) {
            $json['extensions'] = $this->extensions;
        }

        if (!\is_null($this->timeout)) {
            $json['timeout'] = $this->timeout;
        }

        return $json;
    }
}
