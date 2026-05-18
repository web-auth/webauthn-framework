<?php

declare(strict_types=1);

namespace Webauthn\Event;

use Webauthn\CredentialRecord;

/**
 * Event dispatched when the persisted uvInitialized indicator of a credential record changes.
 *
 * Per the WebAuthn Level 3 specification, "updating uvInitialized from false to true SHOULD require
 * authorization by an additional authentication factor equivalent to WebAuthn user verification".
 * The library performs the transition automatically as soon as an assertion arrives with UV = 1; this
 * event gives the Relying Party a hook to apply the recommended additional verification. If that
 * additional verification cannot be obtained, the listener is expected to revert the value on the
 * credential record before it is persisted.
 */
final readonly class UvInitializedChangedEvent implements WebauthnEvent
{
    public function __construct(
        public CredentialRecord $credentialRecord,
        public ?bool $previousValue,
        public ?bool $newValue
    ) {
    }
}
