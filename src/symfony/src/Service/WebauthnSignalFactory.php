<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Authentication\Exception\WebauthnAuthenticationFailureException;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Signal\AllAcceptedCredentials;
use Webauthn\Signal\CurrentUserDetails;
use Webauthn\Signal\UnknownCredential;

/**
 * Builds the three W3C WebAuthn L3 §5.1.10 signal payloads from the bundle's own
 * services so applications do not have to re-derive `rpId`, the descriptor list
 * or the user PII themselves.
 *
 * Use from a custom {@see \Webauthn\Bundle\Security\Handler\SuccessHandler} or
 * controller, then hand the produced {@see \Webauthn\Signal\Signal} objects to
 * {@see WebauthnSignalResponse::withSignals()}.
 *
 * @see https://www.w3.org/TR/webauthn-3/#sctn-signal-methods
 */
final readonly class WebauthnSignalFactory
{
    public function __construct(
        private CredentialRecordRepositoryInterface $credentialRepository,
    ) {
    }

    /**
     * Build a {@see UnknownCredential} signal for an assertion that referenced a credential
     * the relying party no longer recognises (e.g. it was deleted server-side).
     *
     * Per W3C §14.6.3 this signal is safe to expose to an unauthenticated caller: the
     * credential id is one the caller already presented, so no PII leaks.
     */
    public function forUnknownCredential(string $rpId, PublicKeyCredentialDescriptor $credential): UnknownCredential
    {
        return new UnknownCredential($this->rpEntity($rpId), $credential);
    }

    /**
     * Convenience companion to {@see self::forUnknownCredential()} for the
     * Authenticator/Passport/Badge flow: builds the signal from a
     * {@see WebauthnAuthenticationFailureException} raised by
     * {@see \Webauthn\Bundle\Security\Authentication\WebauthnBadgeListener}.
     *
     * Returns `null` when the exception does not carry a deserialized
     * credential (e.g. the failure happened before deserialization could
     * recover the presented `rawId`).
     */
    public function forUnknownCredentialFromException(
        string $rpId,
        WebauthnAuthenticationFailureException $exception,
    ): ?UnknownCredential {
        $credential = $exception->publicKeyCredential;
        if ($credential === null) {
            return null;
        }

        return $this->forUnknownCredential($rpId, $credential->getPublicKeyCredentialDescriptor());
    }

    /**
     * Build an {@see AllAcceptedCredentials} signal containing every credential currently
     * registered for `$user`. The list is derived exhaustively from
     * {@see CredentialRecordRepositoryInterface::findAllForUserEntity()} to defuse the
     * *"potentially irreversible"* deletion warning of W3C §5.1.10.3 (credentials missing
     * from the list are removed/hidden by the authenticator).
     *
     * Per W3C §14.6.3 this signal MUST only be emitted to an authenticated user: the
     * full credential id list is PII.
     */
    public function forAllAccepted(string $rpId, PublicKeyCredentialUserEntity $user): AllAcceptedCredentials
    {
        $descriptors = array_map(
            static fn (CredentialRecord $record): PublicKeyCredentialDescriptor => $record->getPublicKeyCredentialDescriptor(),
            $this->credentialRepository->findAllForUserEntity($user),
        );

        return new AllAcceptedCredentials($this->rpEntity($rpId), $user, $descriptors);
    }

    /**
     * Build a {@see CurrentUserDetails} signal carrying the user's current `name` and
     * `displayName` so the password manager can refresh its passkey label.
     *
     * Per W3C §14.6.3 this signal MUST only be emitted to an authenticated user:
     * the user handle plus display strings are PII.
     */
    public function forCurrentUser(string $rpId, PublicKeyCredentialUserEntity $user): CurrentUserDetails
    {
        return new CurrentUserDetails($this->rpEntity($rpId), $user);
    }

    private function rpEntity(string $rpId): PublicKeyCredentialRpEntity
    {
        return PublicKeyCredentialRpEntity::create(id: $rpId);
    }
}
