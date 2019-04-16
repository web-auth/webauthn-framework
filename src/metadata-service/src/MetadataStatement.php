<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\MetadataService;

use Assert\Assertion;

class MetadataStatement
{
    /**
     * @var string|null
     */
    private $legalHeader;

    /**
     * @var string|null
     */
    private $aaid;

    /**
     * @var string|null
     */
    private $aaguid;
    /**
     * @var string[]
     */
    private $attestationCertificateKeyIdentifiers = [];

    /**
     * @var string
     */
    private $description;

    /**
     * @var string[]
     */
    private $alternativeDescriptions;

    /**
     * @var float
     */
    private $authenticatorVersion;

    /**
     * @var string
     */
    private $protocolFamily;

    /**
     * @var Version[]
     */
    private $upv;

    /**
     * @var string|null
     */
    private $assertionScheme;

    /**
     * @var float|null
     */
    private $authenticationAlgorithm;

    /**
     * @var float[]
     */
    private $authenticationAlgorithms;

    /**
     * @var float|null
     */
    private $publicKeyAlgAndEncoding;

    /**
     * @var float[]
     */
    private $publicKeyAlgAndEncodings;

    /**
     * @var float[]
     */
    private $attestationTypes;

    /**
     * @var VerificationMethodANDCombinations[]
     */
    private $userVerificationDetails;

    /**
     * @var float
     */
    private $keyProtection;

    /**
     * @var bool
     */
    private $isKeyRestricted;

    /**
     * @var bool
     */
    private $isFreshUserVerificationRequired;

    /**
     * @var float
     */
    private $matcherProtection;

    /**
     * @var float|null
     */
    private $cryptoStrength;

    /**
     * @var string|null
     */
    private $operatingEnv;

    /**
     * @var float
     */
    private $attachmentHint;

    /**
     * @var bool
     */
    private $isSecondFactorOnly;

    /**
     * @var float
     */
    private $tcDisplay;

    /**
     * @var string|null
     */
    private $tcDisplayContentType;

    /**
     * @var DisplayPNGCharacteristicsDescriptor[]
     */
    private $tcDisplayPNGCharacteristics;

    /**
     * @var string[]
     */
    private $attestationRootCertificates = [];

    /**
     * @var EcdaaTrustAnchor[]
     */
    private $ecdaaTrustAnchors = [];

    /**
     * @var string|null
     */
    private $icon;

    /**
     * @var ExtensionDescriptor[]
     */
    private $supportedExtensions = [];

    public function getLegalHeader(): ?string
    {
        return $this->legalHeader;
    }

    public function getAaid(): ?string
    {
        return $this->aaid;
    }

    public function getAaguid(): ?string
    {
        return $this->aaguid;
    }

    /**
     * @return string[]
     */
    public function getAttestationCertificateKeyIdentifiers(): array
    {
        return $this->attestationCertificateKeyIdentifiers;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    /**
     * @return string[]
     */
    public function getAlternativeDescriptions(): array
    {
        return $this->alternativeDescriptions;
    }

    public function getAuthenticatorVersion(): float
    {
        return $this->authenticatorVersion;
    }

    public function getProtocolFamily(): string
    {
        return $this->protocolFamily;
    }

    /**
     * @return Version[]
     */
    public function getUpv(): array
    {
        return $this->upv;
    }

    public function getAssertionScheme(): ?string
    {
        return $this->assertionScheme;
    }

    public function getAuthenticationAlgorithm(): ?float
    {
        return $this->authenticationAlgorithm;
    }

    /**
     * @return float[]
     */
    public function getAuthenticationAlgorithms(): array
    {
        return $this->authenticationAlgorithms;
    }

    public function getPublicKeyAlgAndEncoding(): ?float
    {
        return $this->publicKeyAlgAndEncoding;
    }

    /**
     * @return float[]
     */
    public function getPublicKeyAlgAndEncodings(): array
    {
        return $this->publicKeyAlgAndEncodings;
    }

    /**
     * @return float[]
     */
    public function getAttestationTypes(): array
    {
        return $this->attestationTypes;
    }

    /**
     * @return VerificationMethodANDCombinations[]
     */
    public function getUserVerificationDetails(): array
    {
        return $this->userVerificationDetails;
    }

    public function getKeyProtection(): float
    {
        return $this->keyProtection;
    }

    public function isKeyRestricted(): bool
    {
        return $this->isKeyRestricted;
    }

    public function isFreshUserVerificationRequired(): bool
    {
        return $this->isFreshUserVerificationRequired;
    }

    public function getMatcherProtection(): float
    {
        return $this->matcherProtection;
    }

    public function getCryptoStrength(): ?float
    {
        return $this->cryptoStrength;
    }

    public function getOperatingEnv(): ?string
    {
        return $this->operatingEnv;
    }

    public function getAttachmentHint(): float
    {
        return $this->attachmentHint;
    }

    public function isSecondFactorOnly(): bool
    {
        return $this->isSecondFactorOnly;
    }

    public function getTcDisplay(): float
    {
        return $this->tcDisplay;
    }

    public function getTcDisplayContentType(): ?string
    {
        return $this->tcDisplayContentType;
    }

    /**
     * @return DisplayPNGCharacteristicsDescriptor[]
     */
    public function getTcDisplayPNGCharacteristics(): array
    {
        return $this->tcDisplayPNGCharacteristics;
    }

    /**
     * @return string[]
     */
    public function getAttestationRootCertificates(): array
    {
        return $this->attestationRootCertificates;
    }

    /**
     * @return EcdaaTrustAnchor[]
     */
    public function getEcdaaTrustAnchors(): array
    {
        return $this->ecdaaTrustAnchors;
    }

    public function getIcon(): ?string
    {
        return $this->icon;
    }

    /**
     * @return ExtensionDescriptor[]
     */
    public function getSupportedExtensions(): array
    {
        return $this->supportedExtensions;
    }

    public static function createFromArray(array $data): self
    {
        $object = new self();
        $object->legalHeader = $data['legalHeader'] ?? null;
        $object->aaid = $data['aaid'] ?? null;
        $object->aaguid = $data['aaguid'] ?? null;
        $object->attestationCertificateKeyIdentifiers = $data['attestationCertificateKeyIdentifiers'] ?? [];
        $object->description = $data['description'] ?? null;
        $object->alternativeDescriptions = $data['alternativeDescriptions'] ?? [];
        $object->authenticatorVersion = $data['authenticatorVersion'] ?? null;
        $object->protocolFamily = $data['protocolFamily'] ?? null;
        if (isset($data['upv'])) {
            $upv = $data['upv'];
            Assertion::isArray($upv, 'Invalid Metadata Statement');
            foreach ($upv as $value) {
                Assertion::isArray($value, 'Invalid Metadata Statement');
                $object->upv[] = Version::createFromArray($value);
            }
        }
        $object->assertionScheme = $data['assertionScheme'] ?? null;
        $object->authenticationAlgorithm = $data['authenticationAlgorithm'] ?? null;
        $object->authenticationAlgorithms = $data['authenticationAlgorithms'] ?? [];
        $object->publicKeyAlgAndEncoding = $data['publicKeyAlgAndEncoding'] ?? null;
        $object->publicKeyAlgAndEncodings = $data['publicKeyAlgAndEncodings'] ?? [];
        $object->attestationTypes = $data['attestationTypes'] ?? null;
        if (isset($data['userVerificationDetails'])) {
            $userVerificationDetails = $data['userVerificationDetails'];
            Assertion::isArray($userVerificationDetails, 'Invalid Metadata Statement');
            foreach ($userVerificationDetails as $value) {
                Assertion::isArray($value, 'Invalid Metadata Statement');
                $object->userVerificationDetails[] = VerificationMethodANDCombinations::createFromArray($value);
            }
        }
        $object->keyProtection = $data['keyProtection'] ?? null;
        $object->isKeyRestricted = $data['isKeyRestricted'] ?? null;
        $object->isFreshUserVerificationRequired = $data['isFreshUserVerificationRequired'] ?? null;
        $object->matcherProtection = $data['matcherProtection'] ?? null;
        $object->cryptoStrength = $data['cryptoStrength'] ?? null;
        $object->operatingEnv = $data['operatingEnv'] ?? null;
        $object->attachmentHint = $data['attachmentHint'] ?? null;
        $object->isSecondFactorOnly = $data['isSecondFactorOnly'] ?? null;
        $object->tcDisplay = $data['tcDisplay'] ?? null;
        $object->tcDisplayContentType = $data['tcDisplayContentType'] ?? null;
        if (isset($data['tcDisplayPNGCharacteristics'])) {
            $tcDisplayPNGCharacteristics = $data['tcDisplayPNGCharacteristics'];
            Assertion::isArray($tcDisplayPNGCharacteristics, 'Invalid Metadata Statement');
            foreach ($tcDisplayPNGCharacteristics as $tcDisplayPNGCharacteristic) {
                Assertion::isArray($tcDisplayPNGCharacteristic, 'Invalid Metadata Statement');
                $object->tcDisplayPNGCharacteristics[] = DisplayPNGCharacteristicsDescriptor::createFromArray($tcDisplayPNGCharacteristic);
            }
        }
        $object->attestationRootCertificates = $data['attestationRootCertificates'] ?? null;
        $object->ecdaaTrustAnchors = $data['ecdaaTrustAnchors'] ?? null;
        $object->icon = $data['icon'] ?? null;
        if (isset($data['supportedExtensions'])) {
            $supportedExtensions = $data['supportedExtensions'];
            Assertion::isArray($supportedExtensions, 'Invalid Metadata Statement');
            foreach ($supportedExtensions as $supportedExtension) {
                Assertion::isArray($supportedExtension, 'Invalid Metadata Statement');
                $object->supportedExtensions[] = ExtensionDescriptor::createFromArray($supportedExtension);
            }
        }

        return $object;
    }
}
