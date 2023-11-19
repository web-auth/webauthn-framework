<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Event;

use Symfony\Contracts\EventDispatcher\Event;
use Webauthn\PublicKeyCredentialRequestOptions;

class PublicKeyCredentialRequestOptionsCreatedEvent extends Event
{
    public function __construct(
        public readonly PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions
    ) {
    }

    public static function create(PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions): self
    {
        return new self($publicKeyCredentialRequestOptions);
    }

    /**
     * @deprecated since 4.8.0. Will be removed in 5.0.0. Please use the property instead.
     */
    public function getPublicKeyCredentialRequestOptions(): PublicKeyCredentialRequestOptions
    {
        return $this->publicKeyCredentialRequestOptions;
    }
}
