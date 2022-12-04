<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Throwable;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Handler\SuccessHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

final class AttestationResponseController
{
    /**
     * @param string[] $securedRelyingPartyIds
     */
    public function __construct(
        private readonly HttpMessageFactoryInterface $httpMessageFactory,
        private readonly PublicKeyCredentialLoader $publicKeyCredentialLoader,
        private readonly AuthenticatorAttestationResponseValidator $attestationResponseValidator,
        private readonly PublicKeyCredentialSourceRepository $credentialSourceRepository,
        private readonly OptionsStorage $optionStorage,
        private readonly SuccessHandler $successHandler,
        private readonly FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
        private readonly array $securedRelyingPartyIds,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        try {
            $request->getContentType() === 'json' || throw new BadRequestHttpException(
                'Only JSON content type allowed'
            );
            $content = $request->getContent();
            $publicKeyCredential = $this->publicKeyCredentialLoader->load($content);
            $response = $publicKeyCredential->getResponse();
            $response instanceof AuthenticatorAttestationResponse || throw new BadRequestHttpException(
                'Invalid response'
            );

            $storedData = $this->optionStorage->get($response->getClientDataJSON()->getChallenge());

            $publicKeyCredentialCreationOptions = $storedData->getPublicKeyCredentialOptions();
            $publicKeyCredentialCreationOptions instanceof PublicKeyCredentialCreationOptions || throw new BadRequestHttpException(
                'Unable to find the public key credential creation options'
            );
            $userEntity = $storedData->getPublicKeyCredentialUserEntity();
            $userEntity instanceof PublicKeyCredentialUserEntity || throw new BadRequestHttpException(
                'Unable to find the public key credential user entity'
            );
            $psr7Request = $this->httpMessageFactory->createRequest($request);
            $credentialSource = $this->attestationResponseValidator->check(
                $response,
                $publicKeyCredentialCreationOptions,
                $psr7Request,
                $this->securedRelyingPartyIds
            );

            if ($this->credentialSourceRepository->findOneByCredentialId(
                $credentialSource->getPublicKeyCredentialId()
            ) !== null) {
                throw new BadRequestHttpException('The credentials already exists');
            }
            $this->credentialSourceRepository->saveCredentialSource($credentialSource);

            return $this->successHandler->onSuccess($request);
        } catch (Throwable $throwable) {
            if ($this->failureHandler instanceof AuthenticationFailureHandlerInterface) {
                return $this->failureHandler->onAuthenticationFailure(
                    $request,
                    new AuthenticationException($throwable->getMessage(), $throwable->getCode(), $throwable)
                );
            }

            return $this->failureHandler->onFailure($request, $throwable);
        }
    }
}
