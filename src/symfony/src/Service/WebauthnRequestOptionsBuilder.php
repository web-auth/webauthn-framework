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
use Webauthn\FakeCredentialGenerator;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Fluent builder for `PublicKeyCredentialRequestOptions` responses, returned by
 * {@see WebauthnOptionsResponse::forRequest()}.
 *
 * Required: `rpId`. The user entity is optional (assertion can be userless,
 * e.g. usernameless authentication via discoverable credentials) and is set
 * through {@see self::withUser()} when known. When a user entity is resolved,
 * `allowCredentials` is derived from the credential repository unless an
 * explicit list is provided through {@see self::withAllowCredentials()}.
 *
 * When user resolution fails but the JSON body carried a `username` (e.g. a
 * login form posted `{"username":"alice"}`), the builder consults the autowired
 * {@see FakeCredentialGenerator} to produce **fake** `allowCredentials`. This
 * prevents username enumeration: the response shape is identical whether or
 * not the username matches a real user. Disable with
 * {@see self::withFakeCredentialGenerator()} (pass `null`).
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

    private PublicKeyCredentialUserEntity|UserEntityGuesser|null $userOrGuesser = null;

    public function __construct(
        OptionsStorage $storage,
        SerializerInterface $serializer,
        ValidatorInterface $validator,
        CredentialRecordRepositoryInterface $credentialRepository,
        private readonly string $rpId,
        private ?FakeCredentialGenerator $fakeCredentialGenerator = null,
    ) {
        parent::__construct($storage, $serializer, $validator, $credentialRepository);
    }

    public function withUser(PublicKeyCredentialUserEntity|UserEntityGuesser $user): static
    {
        $clone = clone $this;
        $clone->userOrGuesser = $user;

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

    public function withDeriveAllowCredentialsFromUser(bool $derive = true): static
    {
        $clone = clone $this;
        $clone->deriveAllowCredentialsFromUser = $derive;

        return $clone;
    }

    /**
     * @param list<PublicKeyCredentialDescriptor> $descriptors
     */
    public function withAllowCredentials(array $descriptors): static
    {
        $clone = clone $this;
        $clone->allowCredentials = array_values($descriptors);
        $clone->deriveAllowCredentialsFromUser = false;

        return $clone;
    }

    /**
     * Swap the fake credential generator used for username-enumeration
     * protection. Pass `null` to opt out (response will carry empty
     * `allowCredentials` when the username does not resolve to a known user).
     */
    public function withFakeCredentialGenerator(?FakeCredentialGenerator $generator): static
    {
        $clone = clone $this;
        $clone->fakeCredentialGenerator = $generator;

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

    protected function shouldParseClientRequest(): bool
    {
        return parent::shouldParseClientRequest() || $this->fakeCredentialGenerator !== null;
    }

    protected function assembleOptions(
        Request $request,
        ?PublicKeyCredentialUserEntity $userEntity,
        ?object $optionsRequest,
    ): PublicKeyCredentialOptions {
        $allowCredentials = $this->resolveAllowCredentials($request, $userEntity, $optionsRequest);

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
    private function resolveAllowCredentials(
        Request $request,
        ?PublicKeyCredentialUserEntity $userEntity,
        ?object $optionsRequest,
    ): array {
        if ($this->allowCredentials !== null) {
            return $this->allowCredentials;
        }

        if ($userEntity !== null && $this->deriveAllowCredentialsFromUser) {
            return array_map(
                static fn (CredentialRecord $record): PublicKeyCredentialDescriptor => $record->getPublicKeyCredentialDescriptor(),
                $this->credentialRepository->findAllForUserEntity($userEntity),
            );
        }

        if ($userEntity === null
            && $this->fakeCredentialGenerator !== null
            && $optionsRequest instanceof ServerPublicKeyCredentialRequestOptionsRequest
            && $optionsRequest->username !== null
            && $optionsRequest->username !== ''
        ) {
            return array_values($this->fakeCredentialGenerator->generate($request, $optionsRequest->username));
        }

        return [];
    }
}
