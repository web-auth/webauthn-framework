<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Handler\SuccessHandler;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;

final readonly class AssertionResponseController
{
    public function __construct(
        private SerializerInterface $publicKeyCredentialLoader,
        private AuthenticatorAssertionResponseValidator $assertionResponseValidator,
        private LoggerInterface $logger,
        private OptionsStorage $optionsStorage,
        private SuccessHandler $successHandler,
        private FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
        private PublicKeyCredentialSourceRepositoryInterface $publicKeyCredentialSourceRepository
    ) {
    }

    public function __invoke(Request $request): Response
    {
        try {
            $format = $request->getContentTypeFormat();
            $format === 'json' || throw new BadRequestHttpException('Only JSON content type allowed');
            $content = $request->getContent();

            $publicKeyCredential = $this->publicKeyCredentialLoader->deserialize(
                $content,
                PublicKeyCredential::class,
                'json'
            );
            $response = $publicKeyCredential->response;
            $response instanceof AuthenticatorAssertionResponse || throw new BadRequestHttpException(
                'Invalid response'
            );
            $data = $this->optionsStorage->get($response->clientDataJSON->challenge);
            $publicKeyCredentialRequestOptions = $data->getPublicKeyCredentialOptions();
            $publicKeyCredentialRequestOptions instanceof PublicKeyCredentialRequestOptions || throw new BadRequestHttpException(
                'Invalid response'
            );
            $userEntity = $data->getPublicKeyCredentialUserEntity();
            $publicKeyCredentialSource = $this->publicKeyCredentialSourceRepository->findOneByCredentialId(
                $publicKeyCredential->rawId
            );
            $publicKeyCredentialSource !== null || throw AuthenticatorResponseVerificationException::create(
                'The credential ID is invalid.'
            );

            $this->assertionResponseValidator->check(
                $publicKeyCredentialSource,
                $response,
                $publicKeyCredentialRequestOptions,
                $request->getHost(),
                $userEntity?->id,
            );
            return $this->successHandler->onSuccess($request);
        } catch (Throwable $throwable) {
            $this->logger->error($throwable->getMessage());
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
