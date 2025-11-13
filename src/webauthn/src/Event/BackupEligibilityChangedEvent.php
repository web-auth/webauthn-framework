<?php

declare(strict_types=1);

namespace Webauthn\Event;

use Webauthn\PublicKeyCredentialSource;

/**
 * Event dispatched when the backup eligibility flag (BE) changes.
 *
 * The BE flag indicates whether the authenticator is capable of backing up
 * the credential. A change in this flag may indicate device capabilities have changed.
 */
final readonly class BackupEligibilityChangedEvent implements WebauthnEvent
{
    public function __construct(
        public PublicKeyCredentialSource $publicKeyCredentialSource,
        public ?bool $previousValue,
        public ?bool $newValue
    ) {
    }
}
