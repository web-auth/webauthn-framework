<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use LogicException;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialRequestOptionsRequest;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Profile-free, fluent builder for `PublicKeyCredentialRequestOptions` responses.
 *
 * Mirror of {@see WebauthnCreationOptionsResponse} for the assertion ceremony.
 * The application composes the ceremony defaults with `with…()` setters then
 * calls `build($request)` from inside its own controller.
 *
 * Differences with the creation builder:
 *  - the user entity is optional (assertion can be userless, e.g.
 *    usernameless authentication);
 *  - `withRpId()` takes a string (not an `RpEntity`);
 *  - `allowCredentials` is derived from the credential repository when a user
 *    entity is resolved and `withDeriveAllowCredentialsFromUser()` is on
 *    (default), or honours the descriptor list set explicitly via
 *    `withAllowCredentials()`.
 *
 * Each `with…()` returns a clone so the helper stays safe to autowire as a
 * shared service. Required setter: `withRpId()`. Everything else is
 * optional.
 *
 * @see https://www.w3.org/TR/webauthn-3/
 */
final class WebauthnRequestOptionsResponse extends AbstractWebauthnOptionsResponse
{
    private ?string $rpId = null;

    private ?UserEntityGuesser $entityGuesser = null;

    private ?string $userVerification = null;

    private ?string $uiMode = null;

    private bool $deriveAllowCredentialsFromUser = true;

    /**
     * @var list<PublicKeyCredentialDescriptor>|null
     */
    private ?array $allowCredentials = null;

    public function withRpId(string $rpId): static
    {
        $clone = clone $this;
        $clone->rpId = $rpId;

        return $clone;
    }

    public function withEntityGuesser(?UserEntityGuesser $entityGuesser): static
    {
        $clone = clone $this;
        $clone->entityGuesser = $entityGuesser;

        return $clone;
    }

    public function withUserVerification(?string $userVerification): static
    {
        $clone = clone $this;
        $clone->userVerification = $userVerification;

        return $clone;
    }

    public function withUiMode(?string $uiMode): static
    {
        $clone = clone $this;
        $clone->uiMode = $uiMode;

        return $clone;
    }

    /**
     * When `true` (default) and a user entity is resolved, `allowCredentials`
     * is built from {@see \Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface::findAllForUserEntity()}.
     * Set to `false` for usernameless authentication or when explicitly
     * controlling the descriptor list via {@see self::withAllowCredentials()}.
     */
    public function withDeriveAllowCredentialsFromUser(bool $derive = true): static
    {
        $clone = clone $this;
        $clone->deriveAllowCredentialsFromUser = $derive;

        return $clone;
    }

    public function withAllowCredentials(PublicKeyCredentialDescriptor ...$descriptors): static
    {
        $clone = clone $this;
        $clone->allowCredentials = array_values($descriptors);
        $clone->deriveAllowCredentialsFromUser = false;

        return $clone;
    }

    protected function resolveUserEntity(Request $request): ?PublicKeyCredentialUserEntity
    {
        return $this->entityGuesser?->findUserEntity($request);
    }

    protected function parseClientRequest(Request $request): ServerPublicKeyCredentialRequestOptionsRequest
    {
        return $this->parseDto($request, ServerPublicKeyCredentialRequestOptionsRequest::class);
    }

    protected function assembleOptions(
        Request $request,
        ?PublicKeyCredentialUserEntity $userEntity,
        ?object $optionsRequest,
    ): PublicKeyCredentialOptions {
        $rpId = $this->rpId ?? throw new LogicException('withRpId() must be called before build().');

        $allowCredentials = $this->resolveAllowCredentials($userEntity);

        $userVerification = $this->userVerification;
        $extensions = $this->extensions;

        if ($this->clientOverridePolicy !== null && $optionsRequest instanceof ServerPublicKeyCredentialRequestOptionsRequest) {
            /** @var ?string $userVerification */
            $userVerification = $this->clientOverridePolicy->getEffectiveValue(
                'user_verification',
                $optionsRequest->userVerification,
                $userVerification,
            );

            $extensions = $this->mergeExtensions(
                $optionsRequest->extensions,
                $this->clientOverridePolicy
            ) ?? $extensions;
        }

        return PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes($this->challengeLength),
            rpId: $rpId,
            allowCredentials: $allowCredentials,
            userVerification: $userVerification,
            timeout: $this->timeout,
            extensions: $extensions,
            hints: $this->hints,
            uiMode: $this->uiMode,
            attestation: $this->attestation,
            attestationFormats: $this->attestationFormats,
        );
    }

    /**
     * @return list<PublicKeyCredentialDescriptor>
     */
    private function resolveAllowCredentials(?PublicKeyCredentialUserEntity $userEntity): array
    {
        if ($this->allowCredentials !== null) {
            return $this->allowCredentials;
        }

        if (! $this->deriveAllowCredentialsFromUser || $userEntity === null) {
            return [];
        }

        return array_map(
            static fn (CredentialRecord $record): PublicKeyCredentialDescriptor => $record->getPublicKeyCredentialDescriptor(),
            $this->credentialRepository->findAllForUserEntity($userEntity),
        );
    }
}
