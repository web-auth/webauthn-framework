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

namespace Webauthn\MetadataService;

use JsonSerializable;

/**
 * @internal
 */
interface MetadataStatementInterface extends JsonSerializable
{
    public const KEY_PROTECTION_SOFTWARE = 0x0001;
    public const KEY_PROTECTION_HARDWARE = 0x0002;
    public const KEY_PROTECTION_TEE = 0x0004;
    public const KEY_PROTECTION_SECURE_ELEMENT = 0x0008;
    public const KEY_PROTECTION_REMOTE_HANDLE = 0x0010;

    public const MATCHER_PROTECTION_SOFTWARE = 0x0001;
    public const MATCHER_PROTECTION_TEE = 0x0002;
    public const MATCHER_PROTECTION_ON_CHIP = 0x0004;

    public const ATTACHMENT_HINT_INTERNAL = 0x0001;
    public const ATTACHMENT_HINT_EXTERNAL = 0x0002;
    public const ATTACHMENT_HINT_WIRED = 0x0004;
    public const ATTACHMENT_HINT_WIRELESS = 0x0008;
    public const ATTACHMENT_HINT_NFC = 0x0010;
    public const ATTACHMENT_HINT_BLUETOOTH = 0x0020;
    public const ATTACHMENT_HINT_NETWORK = 0x0040;
    public const ATTACHMENT_HINT_READY = 0x0080;
    public const ATTACHMENT_HINT_WIFI_DIRECT = 0x0100;

    public const TRANSACTION_CONFIRMATION_DISPLAY_ANY = 0x0001;
    public const TRANSACTION_CONFIRMATION_DISPLAY_PRIVILEGED_SOFTWARE = 0x0002;
    public const TRANSACTION_CONFIRMATION_DISPLAY_TEE = 0x0004;
    public const TRANSACTION_CONFIRMATION_DISPLAY_HARDWARE = 0x0008;
    public const TRANSACTION_CONFIRMATION_DISPLAY_REMOTE = 0x0010;

    public const ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW = 0x0001;
    public const ALG_SIGN_SECP256R1_ECDSA_SHA256_DER = 0x0002;
    public const ALG_SIGN_RSASSA_PSS_SHA256_RAW = 0x0003;
    public const ALG_SIGN_RSASSA_PSS_SHA256_DER = 0x0004;
    public const ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW = 0x0005;
    public const ALG_SIGN_SECP256K1_ECDSA_SHA256_DER = 0x0006;
    public const ALG_SIGN_SM2_SM3_RAW = 0x0007;
    public const ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW = 0x0008;
    public const ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER = 0x0009;
    public const ALG_SIGN_RSASSA_PSS_SHA384_RAW = 0x000A;
    public const ALG_SIGN_RSASSA_PSS_SHA512_RAW = 0x000B;
    public const ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW = 0x000C;
    public const ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW = 0x000D;
    public const ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW = 0x000E;
    public const ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW = 0x000F;
    public const ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW = 0x0010;
    public const ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW = 0x0011;
    public const ALG_SIGN_ED25519_EDDSA_SHA256_RAW = 0x0012;

    public const ALG_KEY_ECC_X962_RAW = 0x0100;
    public const ALG_KEY_ECC_X962_DER = 0x0101;
    public const ALG_KEY_RSA_2048_RAW = 0x0102;
    public const ALG_KEY_RSA_2048_DER = 0x0103;
    public const ALG_KEY_COSE = 0x0104;

    public const ATTESTATION_BASIC_FULL = 0x3E07;
    public const ATTESTATION_BASIC_SURROGATE = 0x3E08;
    public const ATTESTATION_ECDAA = 0x3E09;
    public const ATTESTATION_ATTCA = 0x3E0A;

    public function getLegalHeader(): ?string;

    public function getAaid(): ?string;

    public function getAaguid(): ?string;

    /**
     * @return string[]
     */
    public function getAttestationCertificateKeyIdentifiers(): array;

    public function getDescription(): string;

    /**
     * @return string[]
     */
    public function getAlternativeDescriptions(): array;

    public function getAuthenticatorVersion(): int;

    public function getProtocolFamily(): string;

    /**
     * @return VersionInterface[]
     */
    public function getUpv(): array;

    public function getAssertionScheme(): ?string;

    public function getAuthenticationAlgorithm(): ?int;

    /**
     * @return int[]
     */
    public function getAuthenticationAlgorithms(): array;

    public function getPublicKeyAlgAndEncoding(): ?int;

    /**
     * @return int[]
     */
    public function getPublicKeyAlgAndEncodings(): array;

    /**
     * @return int[]
     */
    public function getAttestationTypes(): array;

    /**
     * @return VerificationMethodANDCombinationsInterface[]
     */
    public function getUserVerificationDetails(): array;

    public function getKeyProtection(): int;

    public function isKeyRestricted(): ?bool;

    public function isFreshUserVerificationRequired(): ?bool;

    public function getMatcherProtection(): int;

    public function getCryptoStrength(): ?int;

    public function getOperatingEnv(): ?string;

    public function getAttachmentHint(): int;

    public function isSecondFactorOnly(): ?bool;

    public function getTcDisplay(): int;

    public function getTcDisplayContentType(): ?string;

    /**
     * @return DisplayPNGCharacteristicsDescriptorInterface[]
     */
    public function getTcDisplayPNGCharacteristics(): array;

    /**
     * @return string[]
     */
    public function getAttestationRootCertificates(): array;

    /**
     * @return EcdaaTrustAnchorInterface[]
     */
    public function getEcdaaTrustAnchors(): array;

    public function getIcon(): ?string;

    /**
     * @return ExtensionDescriptorInterface[]
     */
    public function getSupportedExtensions(): array;

    public function jsonSerialize(): array;
}
