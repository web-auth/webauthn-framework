<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Webauthn\AuthenticatorResponse;
use Webauthn\Bundle\Security\Authentication\Exception\WebauthnAuthenticationFailureException;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\CeremonyStep\TopOriginValidator;
use Webauthn\CredentialRecord;
use Webauthn\Event\CanDispatchEvents;
use Webauthn\Event\NullEventDispatcher;
use Webauthn\MetadataService\CanLogData;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Common skeleton shared by {@see WebauthnAttestationVerifier} and
 * {@see WebauthnAssertionVerifier}. Reads the JSON body, deserialises it as a
 * {@see PublicKeyCredential}, retrieves the matching ceremony options from
 * {@see OptionsStorage}, and delegates the ceremony-specific validation to
 * subclasses.
 *
 * Pre-validation problems (missing JSON body, malformed payload, wrong response
 * type, unknown challenge) bubble up as {@see BadRequestHttpException} so the
 * Symfony HTTP layer turns them into HTTP 400. Validation failures raised by
 * the underlying validator are wrapped in
 * {@see WebauthnAuthenticationFailureException} so the controller can build a
 * contextual response (e.g. a Signal API payload to drop a stale credential
 * from the platform UI).
 *
 * Implements {@see CanLogData} and {@see CanDispatchEvents} so the bundle's
 * autoconfiguration tags propagate the configured logger and event dispatcher
 * here. Both are forwarded to any one-off validator the verifier may
 * instantiate when {@see self::withAllowedOrigins()} is set.
 */
abstract class AbstractWebauthnVerifier implements CanLogData, CanDispatchEvents
{
    /**
     * @var list<string>|null
     */
    protected ?array $allowedOriginsOverride = null;

    protected bool $allowSubdomainsOverride = false;

    protected ?TopOriginValidator $topOriginValidatorOverride = null;

    protected bool $topOriginValidatorIsOverridden = false;

    protected LoggerInterface $logger;

    protected EventDispatcherInterface $eventDispatcher;

    public function __construct(
        protected readonly SerializerInterface $serializer,
        protected OptionsStorage $storage,
    ) {
        $this->logger = new NullLogger();
        $this->eventDispatcher = new NullEventDispatcher();
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * Override the set of accepted origins for this single verification.
     * Equivalent to the global `webauthn.allowed_origins` configuration but
     * scoped to the current verifier instance: the underlying
     * {@see \Webauthn\CeremonyStep\CeremonyStepManagerFactory} is asked to
     * produce a fresh {@see \Webauthn\CeremonyStep\CeremonyStepManager} that
     * uses these origins, without mutating the factory's global state.
     *
     * @param list<string> $origins
     */
    public function withAllowedOrigins(array $origins): static
    {
        $clone = clone $this;
        $clone->allowedOriginsOverride = array_values($origins);

        return $clone;
    }

    public function withAllowSubdomains(bool $allow = true): static
    {
        $clone = clone $this;
        $clone->allowSubdomainsOverride = $allow;

        return $clone;
    }

    /**
     * Override the top-origin validator used by `CheckTopOrigin` for this single
     * verification. Pass `null` to explicitly disable cross-origin top-origin
     * validation per call (e.g. when the global `top_origin_validator` config
     * is set but a specific endpoint should not enforce it). Triggers the
     * factory-clone path so the global state stays untouched.
     */
    public function withTopOriginValidator(?TopOriginValidator $topOriginValidator): static
    {
        $clone = clone $this;
        $clone->topOriginValidatorOverride = $topOriginValidator;
        $clone->topOriginValidatorIsOverridden = true;

        return $clone;
    }

    /**
     * Override the bundle's `OptionsStorage` for this single verification.
     * Useful for multi-tenant setups where some routes read/write challenges
     * to a different cache than the global default.
     */
    public function withOptionsStorage(OptionsStorage $storage): static
    {
        $clone = clone $this;
        $clone->storage = $storage;

        return $clone;
    }

    public function verify(Request $request): WebauthnVerificationResult
    {
        [$publicKeyCredential, $authenticatorResponse] = $this->loadCredential($request);
        [$options, $userEntity] = $this->loadStoredContext($authenticatorResponse);

        try {
            $credentialRecord = $this->runValidation(
                $request,
                $publicKeyCredential,
                $authenticatorResponse,
                $options,
                $userEntity,
            );
        } catch (Throwable $throwable) {
            throw new WebauthnAuthenticationFailureException(
                $throwable->getMessage(),
                $publicKeyCredential,
                $authenticatorResponse,
                $options,
                $userEntity,
                $throwable,
            );
        }

        return new WebauthnVerificationResult($credentialRecord, $publicKeyCredential, $userEntity);
    }

    abstract protected function ensureResponseMatches(AuthenticatorResponse $response): void;

    abstract protected function ensureOptionsMatch(PublicKeyCredentialOptions $options): void;

    abstract protected function runValidation(
        Request $request,
        PublicKeyCredential $publicKeyCredential,
        AuthenticatorResponse $response,
        PublicKeyCredentialOptions $options,
        ?PublicKeyCredentialUserEntity $userEntity,
    ): CredentialRecord;

    /**
     * @return array{PublicKeyCredential, AuthenticatorResponse}
     */
    private function loadCredential(Request $request): array
    {
        $request->getContentTypeFormat() === 'json' || throw new BadRequestHttpException(
            'Only JSON content type allowed'
        );
        $content = $request->getContent();
        $content !== '' || throw new BadRequestHttpException('Empty request body');

        try {
            $publicKeyCredential = $this->serializer->deserialize($content, PublicKeyCredential::class, 'json');
        } catch (Throwable $throwable) {
            throw new BadRequestHttpException('Unable to deserialize the request body', $throwable);
        }

        $response = $publicKeyCredential->response;
        $this->ensureResponseMatches($response);

        return [$publicKeyCredential, $response];
    }

    /**
     * @return array{PublicKeyCredentialOptions, ?PublicKeyCredentialUserEntity}
     */
    private function loadStoredContext(AuthenticatorResponse $response): array
    {
        try {
            $item = $this->storage->get($response->clientDataJSON->challenge);
        } catch (Throwable $throwable) {
            throw new BadRequestHttpException('No options found for the given challenge', $throwable);
        }

        $options = $item->getPublicKeyCredentialOptions();
        $this->ensureOptionsMatch($options);

        return [$options, $item->getPublicKeyCredentialUserEntity()];
    }
}
