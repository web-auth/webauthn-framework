<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests;

use Assert\Assertion;
use InvalidArgumentException;
use function Safe\sprintf;
use Webauthn\MetadataService\DisplayPNGCharacteristicsDescriptorInterface;
use Webauthn\MetadataService\EcdaaTrustAnchorInterface;
use Webauthn\MetadataService\ExtensionDescriptorInterface;
use Webauthn\MetadataService\MetadataStatementInterface;
use Webauthn\MetadataService\Object\DisplayPNGCharacteristicsDescriptor;
use Webauthn\MetadataService\Object\ExtensionDescriptor;
use Webauthn\MetadataService\Object\VerificationMethodANDCombinations;
use Webauthn\MetadataService\Object\Version;
use Webauthn\MetadataService\VerificationMethodANDCombinationsInterface;
use Webauthn\MetadataService\VersionInterface;

/**
 * @internal
 */
class MetadataStatement implements MetadataStatementInterface
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
    private $alternativeDescriptions = [];

    /**
     * @var int
     */
    private $authenticatorVersion;

    /**
     * @var string
     */
    private $protocolFamily;

    /**
     * @var VersionInterface[]
     */
    private $upv = [];

    /**
     * @var string|null
     */
    private $assertionScheme;

    /**
     * @var int|null
     */
    private $authenticationAlgorithm;

    /**
     * @var int[]
     */
    private $authenticationAlgorithms = [];

    /**
     * @var int|null
     */
    private $publicKeyAlgAndEncoding;

    /**
     * @var int[]
     */
    private $publicKeyAlgAndEncodings = [];

    /**
     * @var int[]
     */
    private $attestationTypes = [];

    /**
     * @var VerificationMethodANDCombinationsInterface[]
     */
    private $userVerificationDetails = [];

    /**
     * @var int
     */
    private $keyProtection;

    /**
     * @var bool|null
     */
    private $isKeyRestricted;

    /**
     * @var bool|null
     */
    private $isFreshUserVerificationRequired;

    /**
     * @var int
     */
    private $matcherProtection;

    /**
     * @var int|null
     */
    private $cryptoStrength;

    /**
     * @var string|null
     */
    private $operatingEnv;

    /**
     * @var int
     */
    private $attachmentHint = 0;

    /**
     * @var bool|null
     */
    private $isSecondFactorOnly;

    /**
     * @var int
     */
    private $tcDisplay;

    /**
     * @var string|null
     */
    private $tcDisplayContentType;

    /**
     * @var DisplayPNGCharacteristicsDescriptorInterface[]
     */
    private $tcDisplayPNGCharacteristics = [];

    /**
     * @var string[]
     */
    private $attestationRootCertificates = [];

    /**
     * @var EcdaaTrustAnchorInterface[]
     */
    private $ecdaaTrustAnchors = [];

    /**
     * @var string|null
     */
    private $icon;

    /**
     * @var ExtensionDescriptorInterface[]
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

    public function getAuthenticatorVersion(): int
    {
        return $this->authenticatorVersion;
    }

    public function getProtocolFamily(): string
    {
        return $this->protocolFamily;
    }

    /**
     * @return VersionInterface[]
     */
    public function getUpv(): array
    {
        return $this->upv;
    }

    public function getAssertionScheme(): ?string
    {
        return $this->assertionScheme;
    }

    public function getAuthenticationAlgorithm(): ?int
    {
        return $this->authenticationAlgorithm;
    }

    /**
     * @return int[]
     */
    public function getAuthenticationAlgorithms(): array
    {
        return $this->authenticationAlgorithms;
    }

    public function getPublicKeyAlgAndEncoding(): ?int
    {
        return $this->publicKeyAlgAndEncoding;
    }

    /**
     * @return int[]
     */
    public function getPublicKeyAlgAndEncodings(): array
    {
        return $this->publicKeyAlgAndEncodings;
    }

    /**
     * @return int[]
     */
    public function getAttestationTypes(): array
    {
        return $this->attestationTypes;
    }

    /**
     * @return VerificationMethodANDCombinationsInterface[]
     */
    public function getUserVerificationDetails(): array
    {
        return $this->userVerificationDetails;
    }

    public function getKeyProtection(): int
    {
        return $this->keyProtection;
    }

    public function isKeyRestricted(): ?bool
    {
        return (bool) $this->isKeyRestricted;
    }

    public function isFreshUserVerificationRequired(): ?bool
    {
        return (bool) $this->isFreshUserVerificationRequired;
    }

    public function getMatcherProtection(): int
    {
        return $this->matcherProtection;
    }

    public function getCryptoStrength(): ?int
    {
        return $this->cryptoStrength;
    }

    public function getOperatingEnv(): ?string
    {
        return $this->operatingEnv;
    }

    public function getAttachmentHint(): int
    {
        return $this->attachmentHint;
    }

    public function isSecondFactorOnly(): ?bool
    {
        return (bool) $this->isSecondFactorOnly;
    }

    public function getTcDisplay(): int
    {
        return $this->tcDisplay;
    }

    public function getTcDisplayContentType(): ?string
    {
        return $this->tcDisplayContentType;
    }

    /**
     * @return DisplayPNGCharacteristicsDescriptorInterface[]
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
     * @return EcdaaTrustAnchorInterface[]
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
     * @return ExtensionDescriptorInterface[]
     */
    public function getSupportedExtensions(): array
    {
        return $this->supportedExtensions;
    }

    public static function createFromString(string $data): self
    {
        return self::createFromArray(json_decode($data, true));
    }

    public static function createFromArray(array $data): self
    {
        $object = new self();
        foreach (['description', 'protocolFamily'] as $key) {
            if (!isset($data[$key])) {
                throw new InvalidArgumentException(sprintf('The parameter "%s" is missing', $key));
            }
        }
        $object->legalHeader = $data['legalHeader'] ?? null;
        $object->aaid = $data['aaid'] ?? null;
        $object->aaguid = $data['aaguid'] ?? null;
        $object->attestationCertificateKeyIdentifiers = $data['attestationCertificateKeyIdentifiers'] ?? [];
        $object->description = $data['description'];
        $object->alternativeDescriptions = $data['alternativeDescriptions'] ?? [];
        $object->authenticatorVersion = $data['authenticatorVersion'] ?? 0;
        $object->protocolFamily = $data['protocolFamily'];
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
        $object->attestationTypes = $data['attestationTypes'] ?? [];
        if (isset($data['userVerificationDetails'])) {
            $userVerificationDetails = $data['userVerificationDetails'];
            Assertion::isArray($userVerificationDetails, 'Invalid Metadata Statement');
            foreach ($userVerificationDetails as $value) {
                Assertion::isArray($value, 'Invalid Metadata Statement');
                $object->userVerificationDetails[] = VerificationMethodANDCombinations::createFromArray($value);
            }
        }
        $object->keyProtection = $data['keyProtection'] ?? 0;
        $object->isKeyRestricted = $data['isKeyRestricted'] ?? null;
        $object->isFreshUserVerificationRequired = $data['isFreshUserVerificationRequired'] ?? null;
        $object->matcherProtection = $data['matcherProtection'] ?? 0;
        $object->cryptoStrength = $data['cryptoStrength'] ?? null;
        $object->operatingEnv = $data['operatingEnv'] ?? null;
        $object->attachmentHint = $data['attachmentHint'] ?? 0;
        $object->isSecondFactorOnly = $data['isSecondFactorOnly'] ?? null;
        $object->tcDisplay = $data['tcDisplay'] ?? 0;
        $object->tcDisplayContentType = $data['tcDisplayContentType'] ?? null;
        if (isset($data['tcDisplayPNGCharacteristics'])) {
            $tcDisplayPNGCharacteristics = $data['tcDisplayPNGCharacteristics'];
            Assertion::isArray($tcDisplayPNGCharacteristics, 'Invalid Metadata Statement');
            foreach ($tcDisplayPNGCharacteristics as $tcDisplayPNGCharacteristic) {
                Assertion::isArray($tcDisplayPNGCharacteristic, 'Invalid Metadata Statement');
                $object->tcDisplayPNGCharacteristics[] = DisplayPNGCharacteristicsDescriptor::createFromArray($tcDisplayPNGCharacteristic);
            }
        }
        $object->attestationRootCertificates = $data['attestationRootCertificates'] ?? [];
        $object->ecdaaTrustAnchors = $data['ecdaaTrustAnchors'] ?? [];
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

    public function jsonSerialize(): array
    {
        return [
            'legalHeader' => $this->legalHeader,
            'aaid' => $this->aaid,
            'aaguid' => $this->aaguid,
            'attestationCertificateKeyIdentifiers' => $this->attestationCertificateKeyIdentifiers,
            'description' => $this->description,
            'alternativeDescriptions' => $this->alternativeDescriptions,
            'authenticatorVersion' => $this->authenticatorVersion,
            'protocolFamily' => $this->protocolFamily,
            'upv' => $this->upv,
            'assertionScheme' => $this->assertionScheme,
            'authenticationAlgorithm' => $this->authenticationAlgorithm,
            'authenticationAlgorithms' => $this->authenticationAlgorithms,
            'publicKeyAlgAndEncoding' => $this->publicKeyAlgAndEncoding,
            'publicKeyAlgAndEncodings' => $this->publicKeyAlgAndEncodings,
            'attestationTypes' => $this->attestationTypes,
            'userVerificationDetails' => $this->userVerificationDetails,
            'keyProtection' => $this->keyProtection,
            'isKeyRestricted' => $this->isKeyRestricted,
            'isFreshUserVerificationRequired' => $this->isFreshUserVerificationRequired,
            'matcherProtection' => $this->matcherProtection,
            'cryptoStrength' => $this->cryptoStrength,
            'operatingEnv' => $this->operatingEnv,
            'attachmentHint' => $this->attachmentHint,
            'isSecondFactorOnly' => $this->isSecondFactorOnly,
            'tcDisplay' => $this->tcDisplay,
            'tcDisplayContentType' => $this->tcDisplayContentType,
            'tcDisplayPNGCharacteristics' => array_map(static function (DisplayPNGCharacteristicsDescriptor $object): array {
                return $object->jsonSerialize();
            }, $this->tcDisplayPNGCharacteristics),
            'attestationRootCertificates' => $this->attestationRootCertificates,
            'ecdaaTrustAnchors' => array_map(static function (EcdaaTrustAnchor $object): array {
                return $object->jsonSerialize();
            }, $this->ecdaaTrustAnchors),
            'icon' => $this->icon,
            'supportedExtensions' => array_map(static function (ExtensionDescriptor $object): array {
                return $object->jsonSerialize();
            }, $this->supportedExtensions),
        ];
    }
}
