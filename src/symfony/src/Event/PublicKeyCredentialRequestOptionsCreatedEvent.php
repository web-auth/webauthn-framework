<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Event;

use JetBrains\PhpStorm\Pure;
use Symfony\Contracts\EventDispatcher\Event;
use Webauthn\PublicKeyCredentialRequestOptions;

class PublicKeyCredentialRequestOptionsCreatedEvent extends Event
{
    #[Pure]
    public function __construct(private PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions)
    {
    }

    #[Pure]
    public function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialRequestOptions
    {
        return $this->publicKeyCredentialRequestOptions;
    }
}
