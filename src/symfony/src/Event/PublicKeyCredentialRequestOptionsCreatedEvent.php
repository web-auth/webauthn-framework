<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Event;

use Symfony\Contracts\EventDispatcher\Event;
use Webauthn\PublicKeyCredentialRequestOptions;

class PublicKeyCredentialRequestOptionsCreatedEvent extends Event
{
    public function __construct(
        private readonly PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions
    ) {
    }

    public static function create(PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions): self
    {
        return new self($publicKeyCredentialRequestOptions);
    }

    public function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialRequestOptions
    {
        return $this->publicKeyCredentialRequestOptions;
    }
}
