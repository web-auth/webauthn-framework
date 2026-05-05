<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Webauthn\AuthenticatorResponse;
use Webauthn\Bundle\Security\Authentication\Exception\WebauthnAuthenticationFailureException;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\CredentialRecord;
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
 */
abstract class AbstractWebauthnVerifier
{
    public function __construct(
        protected readonly SerializerInterface $serializer,
        protected readonly OptionsStorage $storage,
    ) {
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
