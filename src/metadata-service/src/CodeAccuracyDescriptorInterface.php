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
interface CodeAccuracyDescriptorInterface extends AbstractDescriptorInterface
{
    public function getBase(): int;

    public function getMinLength(): int;
}
