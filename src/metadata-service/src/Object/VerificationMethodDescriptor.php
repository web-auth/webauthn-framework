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

namespace Webauthn\MetadataService\Object;

use Assert\Assertion;
use function Safe\sprintf;
use Webauthn\MetadataService\BiometricAccuracyDescriptorInterface;
use Webauthn\MetadataService\CodeAccuracyDescriptorInterface;
use Webauthn\MetadataService\PatternAccuracyDescriptorInterface;
use Webauthn\MetadataService\VerificationMethodDescriptorInterface;

class VerificationMethodDescriptor implements VerificationMethodDescriptorInterface
{
    /**
     * @var int
     */
    private $userVerification;

    /**
     * @var CodeAccuracyDescriptorInterface|null
     */
    private $caDesc;

    /**
     * @var BiometricAccuracyDescriptorInterface|null
     */
    private $baDesc;

    /**
     * @var PatternAccuracyDescriptorInterface|null
     */
    private $paDesc;

    public function __construct(int $userVerification, ?CodeAccuracyDescriptorInterface $caDesc = null, ?BiometricAccuracyDescriptorInterface $baDesc = null, ?PatternAccuracyDescriptorInterface $paDesc = null)
    {
        Assertion::greaterOrEqualThan($userVerification, 0, Utils::logicException('The parameter "userVerification" is invalid'));
        $this->userVerification = $userVerification;
        $this->caDesc = $caDesc;
        $this->baDesc = $baDesc;
        $this->paDesc = $paDesc;
    }

    public function getUserVerification(): int
    {
        return $this->userVerification;
    }

    public function userPresence(): bool
    {
        return 0 !== ($this->userVerification & VerificationMethodDescriptorInterface::USER_VERIFY_PRESENCE);
    }

    public function fingerprint(): bool
    {
        return 0 !== ($this->userVerification & VerificationMethodDescriptorInterface::USER_VERIFY_FINGERPRINT);
    }

    public function passcode(): bool
    {
        return 0 !== ($this->userVerification & VerificationMethodDescriptorInterface::USER_VERIFY_PASSCODE);
    }

    public function voicePrint(): bool
    {
        return 0 !== ($this->userVerification & VerificationMethodDescriptorInterface::USER_VERIFY_VOICEPRINT);
    }

    public function facePrint(): bool
    {
        return 0 !== ($this->userVerification & VerificationMethodDescriptorInterface::USER_VERIFY_FACEPRINT);
    }

    public function location(): bool
    {
        return 0 !== ($this->userVerification & VerificationMethodDescriptorInterface::USER_VERIFY_LOCATION);
    }

    public function eyePrint(): bool
    {
        return 0 !== ($this->userVerification & VerificationMethodDescriptorInterface::USER_VERIFY_EYEPRINT);
    }

    public function pattern(): bool
    {
        return 0 !== ($this->userVerification & VerificationMethodDescriptorInterface::USER_VERIFY_PATTERN);
    }

    public function handprint(): bool
    {
        return 0 !== ($this->userVerification & VerificationMethodDescriptorInterface::USER_VERIFY_HANDPRINT);
    }

    public function none(): bool
    {
        return 0 !== ($this->userVerification & VerificationMethodDescriptorInterface::USER_VERIFY_NONE);
    }

    public function all(): bool
    {
        return 0 !== ($this->userVerification & VerificationMethodDescriptorInterface::USER_VERIFY_ALL);
    }

    public function getCaDesc(): ?CodeAccuracyDescriptorInterface
    {
        return $this->caDesc;
    }

    public function getBaDesc(): ?BiometricAccuracyDescriptorInterface
    {
        return $this->baDesc;
    }

    public function getPaDesc(): ?PatternAccuracyDescriptorInterface
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
