<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\Bundle\Dto\ServerPublicKeyCredentialRequestOptionsRequest;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Fluent builder for `PublicKeyCredentialRequestOptions` responses, returned by
 * {@see WebauthnOptionsResponse::forRequest()}.
 *
 * Required: `rpId`. The user entity is optional (assertion can be userless,
 * e.g. usernameless authentication via discoverable credentials). When a user
 * entity is resolved, `allowCredentials` is derived from the credential
 * repository unless an explicit list is provided through
 * {@see self::withAllowCredentials()}.
 */
final class WebauthnRequestOptionsBuilder extends AbstractWebauthnOptionsBuilder
{
    private ?string $userVerification = null;

    private ?string $uiMode = null;

    private bool $deriveAllowCredentialsFromUser = true;

    /**
     * @var list<PublicKeyCredentialDescriptor>|null
     */
    private ?array $allowCredentials = null;

    public function __construct(
        OptionsStorage $storage,
        SerializerInterface $serializer,
        ValidatorInterface $validator,
        CredentialRecordRepositoryInterface $credentialRepository,
        private readonly string $rpId,
        private readonly PublicKeyCredentialUserEntity|UserEntityGuesser|null $userOrGuesser = null,
    ) {
        parent::__construct($storage, $serializer, $validator, $credentialRepository);
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
        return self::resolveStaticOrGuessed($this->userOrGuesser, $request);
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
                $this->clientOverridePolicy,
            ) ?? $extensions;
        }

        return PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes($this->challengeLength),
            rpId: $this->rpId,
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
