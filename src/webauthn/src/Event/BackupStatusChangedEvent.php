<?php

declare(strict_types=1);

namespace Webauthn\Event;

use Webauthn\PublicKeyCredentialSource;

/**
 * Event dispatched when the backup status flag (BS) changes.
 *
 * The BS flag indicates whether the credential is currently backed up.
 * A change in this flag, especially from true to false, may indicate
 * that the user should add an additional authenticator for redundancy.
 */
final readonly class BackupStatusChangedEvent implements WebauthnEvent
{
    public function __construct(
        public PublicKeyCredentialSource $publicKeyCredentialSource,
        public ?bool $previousValue,
        public ?bool $newValue
    ) {
    }
}
