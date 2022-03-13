<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use Assert\Assertion;
use JsonSerializable;
use Webauthn\MetadataService\Utils;

class VerificationMethodDescriptor implements JsonSerializable
{
    public const USER_VERIFY_PRESENCE_INTERNAL = 'presence_internal';

    public const USER_VERIFY_FINGERPRINT_INTERNAL = 'fingerprint_internal';

    public const USER_VERIFY_PASSCODE_INTERNAL = 'passcode_internal';

    public const USER_VERIFY_VOICEPRINT_INTERNAL = 'voiceprint_internal';

    public const USER_VERIFY_FACEPRINT_INTERNAL = 'faceprint_internal';

    public const USER_VERIFY_LOCATION_INTERNAL = 'location_internal';

    public const USER_VERIFY_EYEPRINT_INTERNAL = 'eyeprint_internal';

    public const USER_VERIFY_PATTERN_INTERNAL = 'pattern_internal';

    public const USER_VERIFY_HANDPRINT_INTERNAL = 'handprint_internal';

    public const USER_VERIFY_PASSCODE_EXTERNAL = 'passcode_external';

    public const USER_VERIFY_PATTERN_EXTERNAL = 'pattern_external';

    public const USER_VERIFY_NONE = 'none';

    public const USER_VERIFY_ALL = 'all';

    private string $userVerificationMethod;

    public function __construct(
        string $userVerificationMethod,
        private ?CodeAccuracyDescriptor $caDesc = null,
        private ?BiometricAccuracyDescriptor $baDesc = null,
        private ?PatternAccuracyDescriptor $paDesc = null
    ) {
        Assertion::greaterOrEqualThan(
            $userVerificationMethod,
            0,
            'The parameter "userVerificationMethod" is invalid'
        );
        $this->userVerificationMethod = $userVerificationMethod;
    }

    public function getUserVerification(): string
    {
        return $this->userVerification;
    }

    public function userPresence(): bool
    {
        return $this->userVerification === self::USER_VERIFY_PRESENCE_INTERNAL;
    }

    public function fingerprint(): bool
    {
        return $this->userVerification === self::USER_VERIFY_FINGERPRINT_INTERNAL;
    }

    public function passcodeInternal(): bool
    {
        return $this->userVerification === self::USER_VERIFY_PASSCODE_INTERNAL;
    }

    public function voicePrint(): bool
    {
        return $this->userVerification === self::USER_VERIFY_VOICEPRINT_INTERNAL;
    }

    public function facePrint(): bool
    {
        return $this->userVerification === self::USER_VERIFY_FACEPRINT_INTERNAL;
    }

    public function location(): bool
    {
        return $this->userVerification === self::USER_VERIFY_LOCATION_INTERNAL;
    }

    public function eyePrint(): bool
    {
        return $this->userVerification === self::USER_VERIFY_EYEPRINT_INTERNAL;
    }

    public function patternInternal(): bool
    {
        return $this->userVerification === self::USER_VERIFY_PATTERN_INTERNAL;
    }

    public function handprint(): bool
    {
        return $this->userVerification === self::USER_VERIFY_HANDPRINT_INTERNAL;
    }

    public function passcodeExternal(): bool
    {
        return $this->userVerification === self::USER_VERIFY_PASSCODE_EXTERNAL;
    }

    public function patternExternal(): bool
    {
        return $this->userVerification === self::USER_VERIFY_PATTERN_EXTERNAL;
    }

    public function none(): bool
    {
        return $this->userVerification === self::USER_VERIFY_NONE;
    }

    public function all(): bool
    {
        return $this->userVerification === self::USER_VERIFY_ALL;
    }

    public function getCaDesc(): ?CodeAccuracyDescriptor
    {
        return $this->caDesc;
    }

    public function getBaDesc(): ?BiometricAccuracyDescriptor
    {
        return $this->baDesc;
    }

    public function getPaDesc(): ?PatternAccuracyDescriptor
    {
        return $this->paDesc;
    }

    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        if (isset($data['userVerification']) && ! isset($data['userVerificationMethod'])) {
            $data['userVerificationMethod'] = $data['userVerification'];
            unset($data['userVerification']);
        }
        Assertion::keyExists($data, 'userVerificationMethod', 'The parameters "userVerificationMethod" is missing');

        foreach (['caDesc', 'baDesc', 'paDesc'] as $key) {
            if (isset($data[$key])) {
                Assertion::isArray($data[$key], sprintf('Invalid parameter "%s"', $key));
            }
        }

        $caDesc = isset($data['caDesc']) ? CodeAccuracyDescriptor::createFromArray($data['caDesc']) : null;
        $baDesc = isset($data['baDesc']) ? BiometricAccuracyDescriptor::createFromArray($data['baDesc']) : null;
        $paDesc = isset($data['paDesc']) ? PatternAccuracyDescriptor::createFromArray($data['paDesc']) : null;

        return new self($data['userVerificationMethod'], $caDesc, $baDesc, $paDesc);
    }

    public function jsonSerialize(): array
    {
        $data = [
            'userVerificationMethod' => $this->userVerificationMethod,
            'caDesc' => $this->caDesc?->jsonSerialize(),
            'baDesc' => $this->baDesc?->jsonSerialize(),
            'paDesc' => $this->paDesc?->jsonSerialize(),
        ];

        return Utils::filterNullValues($data);
    }
}
