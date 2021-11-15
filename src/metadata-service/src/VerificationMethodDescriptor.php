<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use Assert\Assertion;
use JsonSerializable;

class VerificationMethodDescriptor implements JsonSerializable
{
    public const USER_VERIFY_PRESENCE = 0x00000001;

    public const USER_VERIFY_FINGERPRINT = 0x00000002;

    public const USER_VERIFY_PASSCODE = 0x00000004;

    public const USER_VERIFY_VOICEPRINT = 0x00000008;

    public const USER_VERIFY_FACEPRINT = 0x00000010;

    public const USER_VERIFY_LOCATION = 0x00000020;

    public const USER_VERIFY_EYEPRINT = 0x00000040;

    public const USER_VERIFY_PATTERN = 0x00000080;

    public const USER_VERIFY_HANDPRINT = 0x00000100;

    public const USER_VERIFY_NONE = 0x00000200;

    public const USER_VERIFY_ALL = 0x00000400;

    private int $userVerification;

    public function __construct(
        int $userVerification,
        private ?CodeAccuracyDescriptor $caDesc = null,
        private ?BiometricAccuracyDescriptor $baDesc = null,
        private ?PatternAccuracyDescriptor $paDesc = null
    ) {
        Assertion::greaterOrEqualThan(
            $userVerification,
            0,
            Utils::logicException('The parameter "userVerification" is invalid')
        );
        $this->userVerification = $userVerification;
    }

    public function getUserVerification(): int
    {
        return $this->userVerification;
    }

    public function userPresence(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_PRESENCE);
    }

    public function fingerprint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_FINGERPRINT);
    }

    public function passcode(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_PASSCODE);
    }

    public function voicePrint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_VOICEPRINT);
    }

    public function facePrint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_FACEPRINT);
    }

    public function location(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_LOCATION);
    }

    public function eyePrint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_EYEPRINT);
    }

    public function pattern(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_PATTERN);
    }

    public function handprint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_HANDPRINT);
    }

    public function none(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_NONE);
    }

    public function all(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_ALL);
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
        Assertion::keyExists(
            $data,
            'userVerification',
            Utils::logicException('The parameter "userVerification" is missing')
        );
        Assertion::integer(
            $data['userVerification'],
            Utils::logicException('The parameter "userVerification" is invalid')
        );
        foreach (['caDesc', 'baDesc', 'paDesc'] as $key) {
            if (isset($data[$key])) {
                Assertion::isArray($data[$key], Utils::logicException(sprintf('Invalid parameter "%s"', $key)));
            }
        }

        return new self(
            $data['userVerification'],
            isset($data['caDesc']) ? CodeAccuracyDescriptor::createFromArray($data['caDesc']) : null,
            isset($data['baDesc']) ? BiometricAccuracyDescriptor::createFromArray($data['baDesc']) : null,
            isset($data['paDesc']) ? PatternAccuracyDescriptor::createFromArray($data['paDesc']) : null
        );
    }

    public function jsonSerialize(): array
    {
        $data = [
            'userVerification' => $this->userVerification,
            'caDesc' => $this->caDesc === null ? null : $this->caDesc->jsonSerialize(),
            'baDesc' => $this->baDesc === null ? null : $this->baDesc->jsonSerialize(),
            'paDesc' => $this->paDesc === null ? null : $this->paDesc->jsonSerialize(),
        ];

        return Utils::filterNullValues($data);
    }
}
