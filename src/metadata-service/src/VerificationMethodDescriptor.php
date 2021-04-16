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

use Assert\Assertion;
use JetBrains\PhpStorm\Pure;
use JsonSerializable;
use function Safe\sprintf;

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

    public function __construct(int $userVerification, private ?CodeAccuracyDescriptor $caDesc = null, private ?BiometricAccuracyDescriptor $baDesc = null, private ?PatternAccuracyDescriptor $paDesc = null)
    {
        Assertion::greaterOrEqualThan($userVerification, 0, Utils::logicException('The parameter "userVerification" is invalid'));
        $this->userVerification = $userVerification;
    }

    #[Pure]
    public function getUserVerification(): int
    {
        return $this->userVerification;
    }

    #[Pure]
    public function userPresence(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_PRESENCE);
    }

    #[Pure]
    public function fingerprint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_FINGERPRINT);
    }

    #[Pure]
    public function passcode(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_PASSCODE);
    }

    #[Pure]
    public function voicePrint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_VOICEPRINT);
    }

    #[Pure]
    public function facePrint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_FACEPRINT);
    }

    #[Pure]
    public function location(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_LOCATION);
    }

    #[Pure]
    public function eyePrint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_EYEPRINT);
    }

    #[Pure]
    public function pattern(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_PATTERN);
    }

    #[Pure]
    public function handprint(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_HANDPRINT);
    }

    #[Pure]
    public function none(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_NONE);
    }

    #[Pure]
    public function all(): bool
    {
        return 0 !== ($this->userVerification & self::USER_VERIFY_ALL);
    }

    #[Pure]
    public function getCaDesc(): ?CodeAccuracyDescriptor
    {
        return $this->caDesc;
    }

    #[Pure]
    public function getBaDesc(): ?BiometricAccuracyDescriptor
    {
        return $this->baDesc;
    }

    #[Pure]
    public function getPaDesc(): ?PatternAccuracyDescriptor
    {
        return $this->paDesc;
    }

    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        Assertion::keyExists($data, 'userVerification', Utils::logicException('The parameter "userVerification" is missing'));
        Assertion::integer($data['userVerification'], Utils::logicException('The parameter "userVerification" is invalid'));
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

    #[Pure]
    public function jsonSerialize(): array
    {
        $data = [
            'userVerification' => $this->userVerification,
            'caDesc' => null === $this->caDesc ? null : $this->caDesc->jsonSerialize(),
            'baDesc' => null === $this->baDesc ? null : $this->baDesc->jsonSerialize(),
            'paDesc' => null === $this->paDesc ? null : $this->paDesc->jsonSerialize(),
        ];

        return Utils::filterNullValues($data);
    }
}
