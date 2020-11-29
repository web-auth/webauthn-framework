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

/**
 * @internal
 */
interface BiometricAccuracyDescriptorInterface extends AbstractDescriptorInterface
{
    public function getFAR(): ?float;

    public function getFRR(): ?float;

    public function getEER(): ?float;

    public function getFAAR(): ?float;

    public function getMaxReferenceDataSets(): ?int;
}
