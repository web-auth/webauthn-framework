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

namespace Webauthn\Bundle\Event;

use JetBrains\PhpStorm\Pure;
use Symfony\Contracts\EventDispatcher\Event;
use Webauthn\PublicKeyCredentialCreationOptions;

class PublicKeyCredentialCreationOptionsCreatedEvent extends Event
{
    #[Pure]
    public function __construct(private PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions)
    {
    }

    #[Pure]
    public function getPublicKeyCredentialCreationOptions(): PublicKeyCredentialCreationOptions
    {
        return $this->publicKeyCredentialCreationOptions;
    }
}
