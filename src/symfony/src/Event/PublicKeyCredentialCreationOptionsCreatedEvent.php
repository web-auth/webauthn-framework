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

namespace Webauthn\Bundle\Event;

use Symfony\Contracts\EventDispatcher\Event;
use Webauthn\PublicKeyCredentialCreationOptions;

class PublicKeyCredentialCreationOptionsCreatedEvent extends Event
{
    /**
     * @var PublicKeyCredentialCreationOptions
     */
    private $publicKeyCredentialCreationOptions;

    public function __construct(PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions)
    {
        $this->publicKeyCredentialCreationOptions = $publicKeyCredentialCreationOptions;
    }

    public function getPublicKeyCredentialCreationOptions(): PublicKeyCredentialCreationOptions
    {
        return $this->publicKeyCredentialCreationOptions;
    }
}
