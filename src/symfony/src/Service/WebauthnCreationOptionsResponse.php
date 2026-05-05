<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use function count;
use function is_array;
use LogicException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Dto\PublicKeyCredentialCreationOptionsRequest;
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;

/**
 * Profile-free, fluent builder for `PublicKeyCredentialCreationOptions` responses.
 *
 * The application composes the ceremony defaults with `with…()` setters, then calls
 * `build($request)` from inside its own controller. The terminal step resolves the
 * user entity through the configured guesser, optionally merges any client-supplied
 * overrides allowed by a {@see ClientOverridePolicy}, persists the options through
 * the bundle's `OptionsStorage`, and serialises the result as a `JsonResponse`.
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
final class WebauthnCreationOptionsResponse
{
    private ?PublicKeyCredentialRpEntity $rp = null;

    private ?UserEntityGuesser $entityGuesser = null;

    private ?AuthenticatorSelectionCriteria $authenticatorSelection = null;

    /**
     * @var list<PublicKeyCredentialParameters>|null
     */
    private ?array $pubKeyCredParams = null;

    private ?string $attestation = null;

    /**
     * @var list<string>
     */
    private array $attestationFormats = [];

    private ?AuthenticationExtensions $extensions = null;

    /**
     * @var list<string>
     */
    private array $hints = [];

    private ?string $mediation = null;

    private ?int $timeout = null;

    private int $challengeLength = 32;

    private bool $hideExistingCredentials = false;

    private ?ClientOverridePolicy $clientOverridePolicy = null;

    public function __construct(
        private readonly OptionsStorage $storage,
        private readonly SerializerInterface $serializer,
        private readonly ValidatorInterface $validator,
        private readonly CredentialRecordRepositoryInterface $credentialRepository,
    ) {
    }

    public function withRp(PublicKeyCredentialRpEntity $rp): self
    {
        $clone = clone $this;
        $clone->rp = $rp;

        return $clone;
    }

    public function withEntityGuesser(UserEntityGuesser $entityGuesser): self
    {
        $clone = clone $this;
        $clone->entityGuesser = $entityGuesser;

        return $clone;
    }

    public function withAuthenticatorSelectionCriteria(AuthenticatorSelectionCriteria $authenticatorSelection): self
    {
        $clone = clone $this;
        $clone->authenticatorSelection = $authenticatorSelection;

        return $clone;
    }

    public function withPubKeyCredParams(PublicKeyCredentialParameters ...$params): self
    {
        $clone = clone $this;
        $clone->pubKeyCredParams = array_values($params);

        return $clone;
    }

    public function withAttestation(?string $attestation): self
    {
        $clone = clone $this;
        $clone->attestation = $attestation;

        return $clone;
    }

    public function withAttestationFormats(string ...$formats): self
    {
        $clone = clone $this;
        $clone->attestationFormats = array_values($formats);

        return $clone;
    }

    public function withExtensions(AuthenticationExtensions $extensions): self
    {
        $clone = clone $this;
        $clone->extensions = $extensions;

        return $clone;
    }

    public function withHints(string ...$hints): self
    {
        $clone = clone $this;
        $clone->hints = array_values($hints);

        return $clone;
    }

    public function withMediation(?string $mediation): self
    {
        $clone = clone $this;
        $clone->mediation = $mediation;

        return $clone;
    }

    public function withTimeout(?int $timeout): self
    {
        $clone = clone $this;
        $clone->timeout = $timeout;

        return $clone;
    }

    public function withChallengeLength(int $length): self
    {
        $length >= 1 || throw new LogicException('Challenge length must be >= 1.');
        $clone = clone $this;
        $clone->challengeLength = $length;

        return $clone;
    }

    public function withHideExistingCredentials(bool $hide = true): self
    {
        $clone = clone $this;
        $clone->hideExistingCredentials = $hide;

        return $clone;
    }

    public function withClientOverrides(ClientOverridePolicy $policy): self
    {
        $clone = clone $this;
        $clone->clientOverridePolicy = $policy;

        return $clone;
    }

    public function build(Request $request): JsonResponse
    {
        $rp = $this->rp ?? throw new LogicException('withRp() must be called before build().');
        $guesser = $this->entityGuesser ?? throw new LogicException(
            'withEntityGuesser() must be called before build().'
        );

        $userEntity = $guesser->findUserEntity($request);

        $excludeCredentials = $this->hideExistingCredentials ? [] : array_map(
            static fn (CredentialRecord $record): PublicKeyCredentialDescriptor => $record->getPublicKeyCredentialDescriptor(),
            $this->credentialRepository->findAllForUserEntity($userEntity),
        );

        $authenticatorSelection = $this->authenticatorSelection;
        $attestation = $this->attestation;
        $extensions = $this->extensions;
        $mediation = $this->mediation;

        if ($this->clientOverridePolicy !== null) {
            $optionsRequest = $this->parseClientRequest($request);

            $authenticatorSelection = $this->mergeAuthenticatorSelection(
                $optionsRequest,
                $this->clientOverridePolicy,
            ) ?? $authenticatorSelection;

            $attestation = $this->clientOverridePolicy->getEffectiveValue(
                'attestation_conveyance',
                $optionsRequest->attestation,
                $attestation,
            );

            $mediation = $this->clientOverridePolicy->getEffectiveValue(
                'mediation',
                $optionsRequest->mediation,
                $mediation,
            );

            $extensions = $this->mergeExtensions($optionsRequest, $this->clientOverridePolicy) ?? $extensions;
        }

        $options = PublicKeyCredentialCreationOptions::create(
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

        $this->storage->store(Item::create($options, $userEntity));

        return new JsonResponse(
            $this->serializer->serialize($options, JsonEncoder::FORMAT, [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]),
            json: true,
        );
    }

    private function parseClientRequest(Request $request): PublicKeyCredentialCreationOptionsRequest
    {
        $request->getContentTypeFormat() === 'json' || throw new BadRequestHttpException(
            'Only JSON content type allowed'
        );
        $content = $request->getContent();

        $optionsRequest = $content === ''
            ? new PublicKeyCredentialCreationOptionsRequest()
            : $this->serializer->deserialize(
                $content,
                PublicKeyCredentialCreationOptionsRequest::class,
                JsonEncoder::FORMAT
            );

        $violations = $this->validator->validate($optionsRequest);
        if (count($violations) > 0) {
            throw new BadRequestHttpException((string) $violations);
        }

        return $optionsRequest;
    }

    private function mergeAuthenticatorSelection(
        PublicKeyCredentialCreationOptionsRequest $optionsRequest,
        ClientOverridePolicy $policy,
    ): ?AuthenticatorSelectionCriteria {
        $hasAny = $policy->canOverride('user_verification')
            || $policy->canOverride('authenticator_attachment')
            || $policy->canOverride('resident_key');

        if (! $hasAny) {
            return null;
        }

        $userVerification = $policy->getEffectiveValue('user_verification', $optionsRequest->userVerification, null);
        $authenticatorAttachment = $policy->getEffectiveValue(
            'authenticator_attachment',
            $optionsRequest->authenticatorAttachment,
            null
        );
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

    private function mergeExtensions(
        PublicKeyCredentialCreationOptionsRequest $optionsRequest,
        ClientOverridePolicy $policy,
    ): ?AuthenticationExtensions {
        if (! $policy->canOverride('extensions') || ! is_array($optionsRequest->extensions)) {
            return null;
        }

        $extensions = [];
        foreach ($optionsRequest->extensions as $name => $data) {
            $extensions[] = AuthenticationExtension::create($name, $data);
        }

        return AuthenticationExtensions::create($extensions);
    }
}
