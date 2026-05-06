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
use Webauthn\Bundle\Policy\ClientOverridePolicy;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Common skeleton shared by {@see WebauthnCreationOptionsBuilder} and
 * {@see WebauthnRequestOptionsBuilder}. Holds the state and the build pipeline
 * pieces that do not depend on whether the ceremony is registration or
 * assertion: challenge length, timeout, attestation conveyance, attestation
 * formats, extensions, hints, the optional client override policy, the option
 * storage and the JSON serialization step.
 */
abstract class AbstractWebauthnOptionsBuilder
{
    protected ?string $attestation = null;

    /**
     * @var list<string>
     */
    protected array $attestationFormats = [];

    protected ?AuthenticationExtensions $extensions = null;

    /**
     * @var list<string>
     */
    protected array $hints = [];

    protected ?int $timeout = null;

    protected int $challengeLength = 32;

    protected ?ClientOverridePolicy $clientOverridePolicy = null;

    public function __construct(
        protected OptionsStorage $storage,
        protected readonly SerializerInterface $serializer,
        protected readonly ValidatorInterface $validator,
        protected CredentialRecordRepositoryInterface $credentialRepository,
    ) {
    }

    /**
     * Override the bundle's `OptionsStorage` for this single options build.
     * Useful for multi-tenant setups where some routes write challenges to a
     * different cache than the global default.
     */
    public function withOptionsStorage(OptionsStorage $storage): static
    {
        $clone = clone $this;
        $clone->storage = $storage;

        return $clone;
    }

    /**
     * Override the bundle's `CredentialRecordRepositoryInterface` for this
     * single options build (e.g. multi-tenant lookup of a user's existing
     * credentials from a tenant-scoped store).
     */
    public function withCredentialRepository(CredentialRecordRepositoryInterface $repository): static
    {
        $clone = clone $this;
        $clone->credentialRepository = $repository;

        return $clone;
    }

    public function withAttestation(?string $attestation): static
    {
        $clone = clone $this;
        $clone->attestation = $attestation;

        return $clone;
    }

    /**
     * @param list<string> $formats
     */
    public function withAttestationFormats(array $formats): static
    {
        $clone = clone $this;
        $clone->attestationFormats = array_values($formats);

        return $clone;
    }

    /**
     * @param list<AuthenticationExtension> $extensions
     */
    public function withExtensions(array $extensions): static
    {
        $clone = clone $this;
        $clone->extensions = AuthenticationExtensions::create($extensions);

        return $clone;
    }

    /**
     * @param list<string> $hints
     */
    public function withHints(array $hints): static
    {
        $clone = clone $this;
        $clone->hints = array_values($hints);

        return $clone;
    }

    public function withTimeout(?int $timeout): static
    {
        $clone = clone $this;
        $clone->timeout = $timeout;

        return $clone;
    }

    public function withChallengeLength(int $length): static
    {
        $length >= 1 || throw new LogicException('Challenge length must be >= 1.');
        $clone = clone $this;
        $clone->challengeLength = $length;

        return $clone;
    }

    public function withClientOverrides(ClientOverridePolicy $policy): static
    {
        $clone = clone $this;
        $clone->clientOverridePolicy = $policy;

        return $clone;
    }

    public function build(Request $request): JsonResponse
    {
        $userEntity = $this->resolveUserEntity($request);
        $optionsRequest = $this->shouldParseClientRequest() ? $this->parseClientRequest($request) : null;
        $options = $this->assembleOptions($request, $userEntity, $optionsRequest);

        $this->storage->store(Item::create($options, $userEntity));

        return new JsonResponse(
            $this->serializer->serialize($options, JsonEncoder::FORMAT, [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]),
            json: true,
        );
    }

    /**
     * Hook used by {@see self::build()} to decide whether the request body is
     * worth parsing into the ceremony-specific DTO. Returns `true` when a
     * client override policy is attached; subclasses can override to opt in
     * for additional reasons (e.g. anti-enumeration via a fake credential
     * generator on the request side).
     */
    protected function shouldParseClientRequest(): bool
    {
        return $this->clientOverridePolicy !== null;
    }

    abstract protected function resolveUserEntity(Request $request): ?PublicKeyCredentialUserEntity;

    abstract protected function parseClientRequest(Request $request): object;

    abstract protected function assembleOptions(
        Request $request,
        ?PublicKeyCredentialUserEntity $userEntity,
        ?object $optionsRequest,
    ): PublicKeyCredentialOptions;

    /**
     * Normalises an `entity-or-guesser` constructor argument: a `UserEntityGuesser`
     * is invoked against the current request, anything else (entity or null) is
     * returned as-is.
     */
    final protected static function resolveStaticOrGuessed(
        PublicKeyCredentialUserEntity|UserEntityGuesser|null $userOrGuesser,
        Request $request,
    ): ?PublicKeyCredentialUserEntity {
        return $userOrGuesser instanceof UserEntityGuesser
            ? $userOrGuesser->findUserEntity($request)
            : $userOrGuesser;
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $dtoClass
     *
     * @return T
     */
    final protected function parseDto(Request $request, string $dtoClass): object
    {
        $request->getContentTypeFormat() === 'json' || throw new BadRequestHttpException(
            'Only JSON content type allowed'
        );
        $content = $request->getContent();

        $dto = $content === ''
            ? new $dtoClass()
            : $this->serializer->deserialize($content, $dtoClass, JsonEncoder::FORMAT, [
                AbstractObjectNormalizer::DISABLE_TYPE_ENFORCEMENT => true,
            ]);

        $violations = $this->validator->validate($dto);
        if (count($violations) > 0) {
            $messages = [];
            foreach ($violations as $violation) {
                $messages[] = $violation->getPropertyPath() . ': ' . $violation->getMessage();
            }
            throw new BadRequestHttpException(implode("\n", $messages));
        }

        return $dto;
    }

    /**
     * @param array<string, mixed>|null $clientExtensions
     */
    final protected function mergeExtensions(
        ?array $clientExtensions,
        ClientOverridePolicy $policy,
    ): ?AuthenticationExtensions {
        if (! $policy->canOverride('extensions') || ! is_array($clientExtensions)) {
            return null;
        }

        $extensions = [];
        foreach ($clientExtensions as $name => $data) {
            $extensions[] = AuthenticationExtension::create($name, $data);
        }

        return AuthenticationExtensions::create($extensions);
    }
}
