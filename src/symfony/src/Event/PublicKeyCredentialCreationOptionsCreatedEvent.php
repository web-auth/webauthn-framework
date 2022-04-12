<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Event;

use Symfony\Contracts\EventDispatcher\Event;
use Webauthn\PublicKeyCredentialCreationOptions;

class PublicKeyCredentialCreationOptionsCreatedEvent extends Event
{
    public function __construct(
        private readonly PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions
    ) {
    }

    public function getPublicKeyCredentialCreationOptions(): PublicKeyCredentialCreationOptions
    {
        return $this->publicKeyCredentialCreationOptions;
    }
}
