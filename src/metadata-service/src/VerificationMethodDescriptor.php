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

class VerificationMethodDescriptor
{
    /**
     * @var float
     */
    private $userVerification;

    /**
     * @var CodeAccuracyDescriptor|null
     */
    private $caDesc;

    /**
     * @var BiometricAccuracyDescriptor|null
     */
    private $baDesc;

    /**
     * @var PatternAccuracyDescriptor|null
     */
    private $paDesc;

    public function getUserVerification(): float
    {
        return $this->userVerification;
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
        $object = new self();
        $object->userVerification = $data['userVerification'] ?? null;
        $object->caDesc = isset($data['caDesc']) ? CodeAccuracyDescriptor::createFromArray($data['caDesc']) : null;
        $object->baDesc = isset($data['baDesc']) ? BiometricAccuracyDescriptor::createFromArray($data['baDesc']) : null;
        $object->paDesc = isset($data['paDesc']) ? PatternAccuracyDescriptor::createFromArray($data['paDesc']) : null;

        return $object;
    }
}
