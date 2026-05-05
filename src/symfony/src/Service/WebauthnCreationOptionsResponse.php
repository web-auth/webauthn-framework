<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use LogicException;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\PublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Profile-free, fluent builder for `PublicKeyCredentialCreationOptions` responses.
 *
 * The application composes the ceremony defaults with `with…()` setters then
 * calls `build($request)` from inside its own controller. The terminal step
 * resolves the user entity through the configured guesser, optionally merges
 * any client-supplied overrides allowed by a {@see \Webauthn\Bundle\Policy\ClientOverridePolicy},
 * persists the options through the bundle's `OptionsStorage`, and serialises
 * the result as a `JsonResponse`.
 *
 * Each `with…()` call returns a clone so the helper stays safe to autowire as a
 * shared service: callers cannot accidentally leak state across requests.
 *
 * Required setters: `withRp()` and `withEntityGuesser()`. All other setters are
 * optional. If `withClientOverrides()` is not called, the options are produced
 * exactly as the defaults describe: no client field can influence them.
 *
 * @see https://www.w3.org/TR/webauthn-3/
 */
final class WebauthnCreationOptionsResponse extends AbstractWebauthnOptionsResponse
{
    private ?PublicKeyCredentialRpEntity $rp = null;

    private ?UserEntityGuesser $entityGuesser = null;

    private ?AuthenticatorSelectionCriteria $authenticatorSelection = null;

    /**
     * @var list<PublicKeyCredentialParameters>|null
     */
    private ?array $pubKeyCredParams = null;

    private ?string $mediation = null;

    private bool $hideExistingCredentials = false;

    public function withRp(PublicKeyCredentialRpEntity $rp): static
    {
        $clone = clone $this;
        $clone->rp = $rp;

        return $clone;
    }

    public function withEntityGuesser(UserEntityGuesser $entityGuesser): static
    {
        $clone = clone $this;
        $clone->entityGuesser = $entityGuesser;

        return $clone;
    }

    public function withAuthenticatorSelectionCriteria(AuthenticatorSelectionCriteria $authenticatorSelection): static
    {
        $clone = clone $this;
        $clone->authenticatorSelection = $authenticatorSelection;

        return $clone;
    }

    public function withPubKeyCredParams(PublicKeyCredentialParameters ...$params): static
    {
        $clone = clone $this;
        $clone->pubKeyCredParams = array_values($params);

        return $clone;
    }

    public function withMediation(?string $mediation): static
    {
        $clone = clone $this;
        $clone->mediation = $mediation;

        return $clone;
    }

    public function withHideExistingCredentials(bool $hide = true): static
    {
        $clone = clone $this;
        $clone->hideExistingCredentials = $hide;

        return $clone;
    }

    protected function resolveUserEntity(Request $request): PublicKeyCredentialUserEntity
    {
        $guesser = $this->entityGuesser ?? throw new LogicException(
            'withEntityGuesser() must be called before build().'
        );

        return $guesser->findUserEntity($request);
    }

    protected function parseClientRequest(Request $request): PublicKeyCredentialCreationOptionsRequest
    {
        return $this->parseDto($request, PublicKeyCredentialCreationOptionsRequest::class);
    }

    protected function assembleOptions(
        Request $request,
        ?PublicKeyCredentialUserEntity $userEntity,
        ?object $optionsRequest,
    ): PublicKeyCredentialOptions {
        $rp = $this->rp ?? throw new LogicException('withRp() must be called before build().');
        $userEntity ?? throw new LogicException('A user entity is required for creation options.');

        $excludeCredentials = $this->hideExistingCredentials ? [] : array_map(
            static fn (CredentialRecord $record): PublicKeyCredentialDescriptor => $record->getPublicKeyCredentialDescriptor(),
            $this->credentialRepository->findAllForUserEntity($userEntity),
        );

        $authenticatorSelection = $this->authenticatorSelection;
        $attestation = $this->attestation;
        $extensions = $this->extensions;
        $mediation = $this->mediation;

        if ($this->clientOverridePolicy !== null && $optionsRequest instanceof PublicKeyCredentialCreationOptionsRequest) {
            $authenticatorSelection = $this->mergeAuthenticatorSelection($optionsRequest) ?? $authenticatorSelection;

            /** @var ?string $attestation */
            $attestation = $this->clientOverridePolicy->getEffectiveValue(
                'attestation_conveyance',
                $optionsRequest->attestation,
                $attestation,
            );

            /** @var ?string $mediation */
            $mediation = $this->clientOverridePolicy->getEffectiveValue(
                'mediation',
                $optionsRequest->mediation,
                $mediation,
            );

            $extensions = $this->mergeExtensions(
                $optionsRequest->extensions,
                $this->clientOverridePolicy
            ) ?? $extensions;
        }

        return PublicKeyCredentialCreationOptions::create(
            rp: $rp,
            user: $userEntity,
            challenge: random_bytes($this->challengeLength),
            pubKeyCredParams: $this->pubKeyCredParams ?? [],
            authenticatorSelection: $authenticatorSelection,
            attestation: $attestation,
            excludeCredentials: $excludeCredentials,
            timeout: $this->timeout,
            extensions: $extensions,
            hints: $this->hints,
            mediation: $mediation,
            attestationFormats: $this->attestationFormats,
        );
    }

    private function mergeAuthenticatorSelection(
        PublicKeyCredentialCreationOptionsRequest $optionsRequest,
    ): ?AuthenticatorSelectionCriteria {
        $policy = $this->clientOverridePolicy;
        if ($policy === null) {
            return null;
        }

        $hasAny = $policy->canOverride('user_verification')
            || $policy->canOverride('authenticator_attachment')
            || $policy->canOverride('resident_key');

        if (! $hasAny) {
            return null;
        }

        /** @var ?string $userVerification */
        $userVerification = $policy->getEffectiveValue('user_verification', $optionsRequest->userVerification, null);
        /** @var ?string $authenticatorAttachment */
        $authenticatorAttachment = $policy->getEffectiveValue(
            'authenticator_attachment',
            $optionsRequest->authenticatorAttachment,
            null
        );
        /** @var ?string $residentKey */
        $residentKey = $policy->getEffectiveValue('resident_key', $optionsRequest->residentKey, null);

        if ($userVerification === null && $authenticatorAttachment === null && $residentKey === null) {
            return null;
        }

        return AuthenticatorSelectionCriteria::create(
            authenticatorAttachment: $authenticatorAttachment,
            userVerification: $userVerification ?? AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            residentKey: $residentKey,
        );
    }
}
