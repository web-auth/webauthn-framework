<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Assert\Assertion;
use Psr\Log\LoggerInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Security\Storage\OptionsStorage;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;

final class AssertionResponseController
{
    public function __construct(
        private HttpMessageFactoryInterface $httpMessageFactory,
        private PublicKeyCredentialLoader $publicKeyCredentialLoader,
        private AuthenticatorAssertionResponseValidator $assertionResponseValidator,
        private LoggerInterface $logger,
        private OptionsStorage $optionsStorage,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        try {
            Assertion::eq('json', $request->getContentType(), 'Only JSON content type allowed');
            $content = $request->getContent();
            Assertion::string($content, 'Invalid data');
            $publicKeyCredential = $this->publicKeyCredentialLoader->load($content);
            $response = $publicKeyCredential->getResponse();
            Assertion::isInstanceOf($response, AuthenticatorAssertionResponse::class, 'Invalid response');
            $data = $this->optionsStorage->get();
            $publicKeyCredentialRequestOptions = $data->getPublicKeyCredentialOptions();
            Assertion::isInstanceOf(
                $publicKeyCredentialRequestOptions,
                PublicKeyCredentialRequestOptions::class,
                'Invalid response'
            );
            $userEntity = $data->getPublicKeyCredentialUserEntity();
            $psr7Request = $this->httpMessageFactory->createRequest($request);
            $this->assertionResponseValidator->check(
                $publicKeyCredential->getRawId(),
                $response,
                $publicKeyCredentialRequestOptions,
                $psr7Request,
                $userEntity?->getId()
            );

            return new JsonResponse([
                'status' => 'ok',
                'errorMessage' => '',
            ]);
        } catch (Throwable $throwable) {
            $this->logger->error($throwable->getMessage());

            return new JsonResponse([
                'status' => 'error',
                'errorMessage' => $throwable->getMessage(),
            ], 400);
        }
    }
}
