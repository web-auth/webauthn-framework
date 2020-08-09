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

interface ExtensionDescriptorInterface extends JsonSerializable
{
    public function getId(): string;

    public function getTag(): ?int;

    public function getData(): ?string;

    public function isFailIfUnknown(): bool;

    public function jsonSerialize(): array;
}
