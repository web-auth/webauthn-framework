<?php

declare(strict_types=1);

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
