<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Cose\Algorithms;
use LogicException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\PublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Fluent builder for `PublicKeyCredentialCreationOptions` responses, returned by
 * {@see WebauthnOptionsResponse::forCreation()}.
 *
 * Required pieces (`rpId` and either a `PublicKeyCredentialUserEntity` or a
 * {@see UserEntityGuesser}) are passed straight to the constructor by the
 * factory; everything else is optional and has a sensible default.
 */
final class WebauthnCreationOptionsBuilder extends AbstractWebauthnOptionsBuilder
{
    private ?AuthenticatorSelectionCriteria $authenticatorSelection = null;

    /**
     * @var list<PublicKeyCredentialParameters>
     */
    private array $pubKeyCredParams;

    private ?string $mediation = null;

    private bool $hideExistingCredentials = false;

    private ?string $rpName = null;

    public function __construct(
        OptionsStorage $storage,
        SerializerInterface $serializer,
        ValidatorInterface $validator,
        CredentialRecordRepositoryInterface $credentialRepository,
        private readonly string $rpId,
        private readonly PublicKeyCredentialUserEntity|UserEntityGuesser $userOrGuesser,
    ) {
        parent::__construct($storage, $serializer, $validator, $credentialRepository);
        $this->pubKeyCredParams = self::defaultPubKeyCredParams();
    }

    public function withAuthenticatorSelectionCriteria(AuthenticatorSelectionCriteria $authenticatorSelection): static
    {
        $clone = clone $this;
        $clone->authenticatorSelection = $authenticatorSelection;

        return $clone;
    }

    /**
     * Override the human-palatable Relying Party name advertised to the user
     * agent during the creation ceremony. Defaults to the `rpId` passed to
     * {@see WebauthnOptionsResponse::forCreation()}: per W3C IDL
     * `PublicKeyCredentialEntity.name` is required, and SimpleWebAuthn's
     * browser bindings refuse to register when it is missing, even though
     * recent Chrome / Firefox builds tolerate the absence.
     */
    public function withRpName(string $rpName): static
    {
        $clone = clone $this;
        $clone->rpName = $rpName;

        return $clone;
    }

    /**
     * @param list<PublicKeyCredentialParameters> $params
     */
    public function withPubKeyCredParams(array $params): static
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
        $userEntity = self::resolveStaticOrGuessed($this->userOrGuesser, $request);

        return $userEntity ?? throw new LogicException('A user entity is required for creation options.');
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
                $this->clientOverridePolicy,
            ) ?? $extensions;
        }

        return PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create($this->rpName ?? $this->rpId, $this->rpId),
            user: $userEntity,
            challenge: random_bytes($this->challengeLength),
            pubKeyCredParams: $this->pubKeyCredParams,
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

    /**
     * @return list<PublicKeyCredentialParameters>
     */
    private static function defaultPubKeyCredParams(): array
    {
        return [
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ES256),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_RS256),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_EdDSA),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ES384),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ES512),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_PS256),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_RS384),
            PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_RS512),
        ];
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
            null,
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
