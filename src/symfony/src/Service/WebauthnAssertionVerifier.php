<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use function assert;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorResponse;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Verifies the {@see AuthenticatorAssertionResponse} produced at the end of an
 * authentication ceremony, returned by
 * {@see WebauthnResponseVerifier::forAssertion()}.
 *
 * The credential record matching the response's `rawId` is fetched from the
 * autowired {@see CredentialRecordRepositoryInterface} and updated in place by
 * the underlying validator (counter, backup state, `uvInitialized`). Persistence
 * of these updates is left to the repository implementation, mirroring the
 * legacy {@see \Webauthn\Bundle\Controller\AssertionResponseController}: Doctrine
 * repositories flush automatically through the unit of work.
 *
 * Per-verifier origin overrides are supported through
 * {@see self::withAllowedOrigins()} / {@see self::withAllowSubdomains()}: when
 * set, a fresh validator is built on top of a scoped ceremony step manager so
 * the global `webauthn.allowed_origins` configuration is unaffected.
 */
final class WebauthnAssertionVerifier extends AbstractWebauthnVerifier
{
    public function __construct(
        SerializerInterface $serializer,
        OptionsStorage $storage,
        private readonly AuthenticatorAssertionResponseValidator $validator,
        private readonly CredentialRecordRepositoryInterface $repository,
        private readonly CeremonyStepManagerFactory $ceremonyStepManagerFactory,
        private readonly string $rpId,
    ) {
        parent::__construct($serializer, $storage);
    }

    protected function ensureResponseMatches(AuthenticatorResponse $response): void
    {
        $response instanceof AuthenticatorAssertionResponse || throw new BadRequestHttpException(
            'The response is not an assertion response.'
        );
    }

    protected function ensureOptionsMatch(PublicKeyCredentialOptions $options): void
    {
        $options instanceof PublicKeyCredentialRequestOptions || throw new BadRequestHttpException(
            'The stored options are not request options.'
        );

        ($options->rpId ?? $this->rpId) === $this->rpId || throw new BadRequestHttpException(
            'The stored options do not match the expected Relying Party identifier.'
        );
    }

    protected function runValidation(
        Request $request,
        PublicKeyCredential $publicKeyCredential,
        AuthenticatorResponse $response,
        PublicKeyCredentialOptions $options,
        ?PublicKeyCredentialUserEntity $userEntity,
    ): CredentialRecord {
        assert($response instanceof AuthenticatorAssertionResponse);
        assert($options instanceof PublicKeyCredentialRequestOptions);

        $credentialRecord = $this->repository->findOneByCredentialId($publicKeyCredential->rawId)
            ?? throw AuthenticatorResponseVerificationException::create('The credential ID is invalid.');

        return $this->resolveValidator()
            ->check($credentialRecord, $response, $options, $request->getHost(), $userEntity?->id);
    }

    private function resolveValidator(): AuthenticatorAssertionResponseValidator
    {
        if ($this->allowedOriginsOverride === null) {
            return $this->validator;
        }

        $csm = $this->ceremonyStepManagerFactory->requestCeremony(
            $this->allowedOriginsOverride,
            $this->allowSubdomainsOverride,
        );

        $scoped = new AuthenticatorAssertionResponseValidator($csm);
        $scoped->setLogger($this->logger);
        $scoped->setEventDispatcher($this->eventDispatcher);

        return $scoped;
    }
}
