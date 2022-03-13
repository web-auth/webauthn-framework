<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use Assert\Assertion;
use const JSON_THROW_ON_ERROR;
use JsonSerializable;
use Webauthn\MetadataService\Utils;

class MetadataStatement implements JsonSerializable
{
    public const KEY_PROTECTION_SOFTWARE = 'software';

    public const KEY_PROTECTION_HARDWARE = 'hardware';

    public const KEY_PROTECTION_TEE = 'tee';

    public const KEY_PROTECTION_SECURE_ELEMENT = 'secure_element';

    public const KEY_PROTECTION_REMOTE_HANDLE = 'remote_handle';

    public const MATCHER_PROTECTION_SOFTWARE = 'software';

    public const MATCHER_PROTECTION_TEE = 'tee';

    public const MATCHER_PROTECTION_ON_CHIP = 'on_chip';

    public const ATTACHMENT_HINT_INTERNAL = 'internal';

    public const ATTACHMENT_HINT_EXTERNAL = 'external';

    public const ATTACHMENT_HINT_WIRED = 'wired';

    public const ATTACHMENT_HINT_WIRELESS = 'wireless';

    public const ATTACHMENT_HINT_NFC = 'nfc';

    public const ATTACHMENT_HINT_BLUETOOTH = 'bluetooth';

    public const ATTACHMENT_HINT_NETWORK = 'network';

    public const ATTACHMENT_HINT_READY = 'ready';

    public const ATTACHMENT_HINT_WIFI_DIRECT = 'wifi_direct';

    public const TRANSACTION_CONFIRMATION_DISPLAY_ANY = 'any';

    public const TRANSACTION_CONFIRMATION_DISPLAY_PRIVILEGED_SOFTWARE = 'privileged_software';

    public const TRANSACTION_CONFIRMATION_DISPLAY_TEE = 'tee';

    public const TRANSACTION_CONFIRMATION_DISPLAY_HARDWARE = 'hardware';

    public const TRANSACTION_CONFIRMATION_DISPLAY_REMOTE = 'remote';

    public const ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW = 'secp256r1_ecdsa_sha256_raw';

    public const ALG_SIGN_SECP256R1_ECDSA_SHA256_DER = 'secp256r1_ecdsa_sha256_der';

    public const ALG_SIGN_RSASSA_PSS_SHA256_RAW = 'rsassa_pss_sha256_raw';

    public const ALG_SIGN_RSASSA_PSS_SHA256_DER = 'rsassa_pss_sha256_der';

    public const ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW = 'secp256k1_ecdsa_sha256_raw';

    public const ALG_SIGN_SECP256K1_ECDSA_SHA256_DER = 'secp256k1_ecdsa_sha256_der';

    public const ALG_SIGN_SM2_SM3_RAW = 'sm2_sm3_raw';

    public const ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW = 'rsa_emsa_pkcs1_sha256_raw';

    public const ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER = 'rsa_emsa_pkcs1_sha256_der';

    public const ALG_SIGN_RSASSA_PSS_SHA384_RAW = 'rsassa_pss_sha384_raw';

    public const ALG_SIGN_RSASSA_PSS_SHA512_RAW = 'rsassa_pss_sha256_raw';

    public const ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW = 'rsassa_pkcsv15_sha256_raw';

    public const ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW = 'rsassa_pkcsv15_sha384_raw';

    public const ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW = 'rsassa_pkcsv15_sha512_raw';

    public const ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW = 'rsassa_pkcsv15_sha1_raw';

    public const ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW = 'secp384r1_ecdsa_sha384_raw';

    public const ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW = 'secp512r1_ecdsa_sha256_raw';

    public const ALG_SIGN_ED25519_EDDSA_SHA256_RAW = 'ed25519_eddsa_sha512_raw';

    public const ALG_KEY_ECC_X962_RAW = 'ecc_x962_raw';

    public const ALG_KEY_ECC_X962_DER = 'ecc_x962_der';

    public const ALG_KEY_RSA_2048_RAW = 'rsa_2048_raw';

    public const ALG_KEY_RSA_2048_DER = 'rsa_2048_der';

    public const ALG_KEY_COSE = 'cose';

    public const ATTESTATION_BASIC_FULL = 'basic_full';

    public const ATTESTATION_BASIC_SURROGATE = 'basic_surrogate';

    public const ATTESTATION_ECDAA = 'ecdaa';

    public const ATTESTATION_ATTCA = 'attca';

    private ?string $legalHeader;

    private ?string $aaid;

    private ?string $aaguid;

    /**
     * @var string[]
     */
    private array $attestationCertificateKeyIdentifiers = [];

    private string $description;

    private AlternativeDescriptions $alternativeDescriptions;

    private int $authenticatorVersion;

    private string $protocolFamily;

    private int $schema;

    /**
     * @var Version[]
     */
    private array $upv;

    /**
     * @var string[]
     */
    private array $authenticationAlgorithms;

    /**
     * @var string[]
     */
    private array $publicKeyAlgAndEncodings;

    /**
     * @var string[]
     */
    private array $attestationTypes;

    /**
     * @var VerificationMethodANDCombinations[]
     */
    private array $userVerificationDetails;

    /**
     * @var string[]
     */
    private array $keyProtection;

    private ?bool $isKeyRestricted = null;

    private ?bool $isFreshUserVerificationRequired = null;

    /**
     * @var string[]
     */
    private array $matcherProtection;

    private ?int $cryptoStrength = null;

    /**
     * @var string[]
     */
    private array $attachmentHint = [];

    /**
     * @var string[]
     */
    private array $tcDisplay;

    private ?string $tcDisplayContentType = null;

    /**
     * @var DisplayPNGCharacteristicsDescriptor[]
     */
    private array $tcDisplayPNGCharacteristics = [];

    /**
     * @var string[]
     */
    private array $attestationRootCertificates;

    /**
     * @var EcdaaTrustAnchor[]
     */
    private array $ecdaaTrustAnchors = [];

    private ?string $icon = null;

    /**
     * @var ExtensionDescriptor[]
     */
    private array $supportedExtensions = [];

    private AuthenticatorGetInfo $authenticatorGetInfo;

    public static function createFromString(string $statement): self
    {
        $data = json_decode($statement, true, 512, JSON_THROW_ON_ERROR);
        Assertion::isArray($data, 'Invalid Metadata Statement');

        return self::createFromArray($data);
    }

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

    public function isKeyRestricted(): ?bool
    {
        return $this->isKeyRestricted;
    }

    public function isFreshUserVerificationRequired(): ?bool
    {
        return $this->isFreshUserVerificationRequired;
    }

    public function getAuthenticatorGetInfo(): AuthenticatorGetInfo
    {
        return $this->authenticatorGetInfo;
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

    public function getAlternativeDescriptions(): AlternativeDescriptions
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
     * @return Version[]
     */
    public function getUpv(): array
    {
        return $this->upv;
    }

    public function getSchema(): ?int
    {
        return $this->schema;
    }

    /**
     * @return string[]
     */
    public function getAuthenticationAlgorithms(): array
    {
        return $this->authenticationAlgorithms;
    }

    /**
     * @return string[]
     */
    public function getPublicKeyAlgAndEncodings(): array
    {
        return $this->publicKeyAlgAndEncodings;
    }

    /**
     * @return string[]
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

    /**
     * @return string[]
     */
    public function getKeyProtection(): array
    {
        return $this->keyProtection;
    }

    /**
     * @return string[]
     */
    public function getMatcherProtection(): array
    {
        return $this->matcherProtection;
    }

    public function getCryptoStrength(): ?int
    {
        return $this->cryptoStrength;
    }

    /**
     * @return string[]
     */
    public function getAttachmentHint(): array
    {
        return $this->attachmentHint;
    }

    /**
     * @return string[]
     */
    public function getTcDisplay(): array
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
        $requiredKeys = [
            'description',
            'authenticatorVersion',
            'protocolFamily',
            'schema',
            'upv',
            'authenticationAlgorithms',
            'publicKeyAlgAndEncodings',
            'attestationTypes',
            'userVerificationDetails',
            'matcherProtection',
            'tcDisplay',
            'attestationRootCertificates',
        ];
        $object = new self();
        foreach ($requiredKeys as $key) {
            Assertion::keyExists($data, $key, sprintf('The parameter "%s" is missing', $key));
        }

        $object->description = $data['description'];
        $object->authenticatorVersion = $data['authenticatorVersion'];
        $object->protocolFamily = $data['protocolFamily'];
        $object->schema = $data['schema'];
        $upv = $data['upv'];
        Assertion::isArray($upv, 'Invalid Metadata Statement');
        foreach ($upv as $value) {
            Assertion::isArray($value, 'Invalid Metadata Statement');
            $object->upv[] = Version::createFromArray($value);
        }
        Assertion::allString($data['authenticationAlgorithms'], 'Invalid Metadata Statement');
        $object->authenticationAlgorithms = $data['authenticationAlgorithms'];
        Assertion::allString($data['publicKeyAlgAndEncodings'], 'Invalid Metadata Statement');
        $object->publicKeyAlgAndEncodings = $data['publicKeyAlgAndEncodings'];
        Assertion::allString($data['attestationTypes'], 'Invalid Metadata Statement');
        $object->attestationTypes = $data['attestationTypes'];
        $userVerificationDetails = $data['userVerificationDetails'];
        Assertion::isArray($userVerificationDetails, 'Invalid Metadata Statement');
        foreach ($userVerificationDetails as $value) {
            Assertion::isArray($value, 'Invalid Metadata Statement');
            $object->userVerificationDetails[] = VerificationMethodANDCombinations::createFromArray($value);
        }
        Assertion::allString($data['matcherProtection'], 'Invalid Metadata Statement');
        $object->matcherProtection = $data['matcherProtection'];
        Assertion::allString($data['tcDisplay'], 'Invalid Metadata Statement');
        $object->tcDisplay = $data['tcDisplay'];
        Assertion::allString($data['attestationRootCertificates'], 'Invalid Metadata Statement');
        $object->attestationRootCertificates = $data['attestationRootCertificates'];

        $object->legalHeader = $data['legalHeader'] ?? null;
        $object->aaid = $data['aaid'] ?? null;
        $object->aaguid = $data['aaguid'] ?? null;
        $object->attestationCertificateKeyIdentifiers = $data['attestationCertificateKeyIdentifiers'] ?? [];
        $object->alternativeDescriptions = AlternativeDescriptions::create($data['alternativeDescriptions'] ?? []);
        $object->authenticatorGetInfo = $data['attestationTypes'] ? AuthenticatorGetInfo::create(
            $data['attestationTypes']
        ) : null;
        $object->keyProtection = $data['keyProtection'] ?? [];
        $object->isKeyRestricted = $data['isKeyRestricted'] ?? null;
        $object->isFreshUserVerificationRequired = $data['isFreshUserVerificationRequired'] ?? null;
        $object->cryptoStrength = $data['cryptoStrength'] ?? null;
        $object->attachmentHint = $data['attachmentHint'] ?? [];
        $object->tcDisplayContentType = $data['tcDisplayContentType'] ?? null;
        if (isset($data['tcDisplayPNGCharacteristics'])) {
            $tcDisplayPNGCharacteristics = $data['tcDisplayPNGCharacteristics'];
            Assertion::isArray($tcDisplayPNGCharacteristics, 'Invalid Metadata Statement');
            foreach ($tcDisplayPNGCharacteristics as $tcDisplayPNGCharacteristic) {
                Assertion::isArray($tcDisplayPNGCharacteristic, 'Invalid Metadata Statement');
                $object->tcDisplayPNGCharacteristics[] = DisplayPNGCharacteristicsDescriptor::createFromArray(
                    $tcDisplayPNGCharacteristic
                );
            }
        }
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
        $data = [
            'legalHeader' => $this->legalHeader,
            'aaid' => $this->aaid,
            'aaguid' => $this->aaguid,
            'attestationCertificateKeyIdentifiers' => $this->attestationCertificateKeyIdentifiers,
            'description' => $this->description,
            'alternativeDescriptions' => $this->alternativeDescriptions,
            'authenticatorVersion' => $this->authenticatorVersion,
            'protocolFamily' => $this->protocolFamily,
            'upv' => $this->upv,
            'authenticationAlgorithms' => $this->authenticationAlgorithms,
            'publicKeyAlgAndEncodings' => $this->publicKeyAlgAndEncodings,
            'attestationTypes' => $this->attestationTypes,
            'userVerificationDetails' => $this->userVerificationDetails,
            'keyProtection' => $this->keyProtection,
            'isKeyRestricted' => $this->isKeyRestricted,
            'isFreshUserVerificationRequired' => $this->isFreshUserVerificationRequired,
            'matcherProtection' => $this->matcherProtection,
            'cryptoStrength' => $this->cryptoStrength,
            'attachmentHint' => $this->attachmentHint,
            'tcDisplay' => $this->tcDisplay,
            'tcDisplayContentType' => $this->tcDisplayContentType,
            'tcDisplayPNGCharacteristics' => array_map(
                static function (DisplayPNGCharacteristicsDescriptor $object): array {
                    return $object->jsonSerialize();
                },
                $this->tcDisplayPNGCharacteristics
            ),
            'attestationRootCertificates' => $this->attestationRootCertificates,
            'ecdaaTrustAnchors' => array_map(static function (EcdaaTrustAnchor $object): array {
                return $object->jsonSerialize();
            }, $this->ecdaaTrustAnchors),
            'icon' => $this->icon,
            'authenticatorGetInfo' => $this->authenticatorGetInfo,
            'supportedExtensions' => array_map(static function (ExtensionDescriptor $object): array {
                return $object->jsonSerialize();
            }, $this->supportedExtensions),
        ];

        return Utils::filterNullValues($data);
    }
}
