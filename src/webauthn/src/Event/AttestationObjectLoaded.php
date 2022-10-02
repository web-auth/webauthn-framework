<?php

declare(strict_types=1);

namespace Webauthn\Event;

use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\MetadataService\Event\WebauthnEvent;

class AttestationObjectLoaded implements WebauthnEvent
{
    public function __construct(
        public readonly AttestationObject $attestationObject
    ) {
    }

    public static function create(AttestationObject $attestationObject): self
    {
        return new self($attestationObject);
    }
}
