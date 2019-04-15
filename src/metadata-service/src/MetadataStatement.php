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
     * @var string[
     */
    private $alternativeDescriptions;

    /**
     * @var int
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
     * @var int|null
     */
    private $authenticationAlgorithm;

    /**
     * @var int[]
     */
    private $authenticationAlgorithms;

    /**
     * @var int|null
     */
    private $publicKeyAlgAndEncoding;

    /**
     * @var int[]
     */
    private $publicKeyAlgAndEncodings;

    /**
     * @var int[]
     */
    private $attestationTypes;

    /**
     * @var VerificationMethodANDCombinations[]
     */
    private $userVerificationDetails;

    /**
     * @var int
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
    private $attachmentHint;

    /**
     * @var bool
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
}
