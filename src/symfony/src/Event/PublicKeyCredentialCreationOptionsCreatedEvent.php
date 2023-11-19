<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Event;

use Symfony\Contracts\EventDispatcher\Event;
use Webauthn\PublicKeyCredentialCreationOptions;

class PublicKeyCredentialCreationOptionsCreatedEvent extends Event
{
    public function __construct(
        public readonly PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions
    ) {
    }

    public static function create(PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions): self
    {
        return new self($publicKeyCredentialCreationOptions);
    }

    /**
     * @deprecated since 4.8.0. Will be removed in 5.0.0. Please use the property instead.
     */
    public function getPublicKeyCredentialCreationOptions(): PublicKeyCredentialCreationOptions
    {
        return $this->publicKeyCredentialCreationOptions;
    }
}
