<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Event;

use Symfony\Contracts\EventDispatcher\Event;
use Webauthn\PublicKeyCredentialRequestOptions;

class PublicKeyCredentialRequestOptionsCreatedEvent extends Event
{
    public function __construct(
        private PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions
    ) {
    }

    public function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialRequestOptions
    {
        return $this->publicKeyCredentialRequestOptions;
    }
}
