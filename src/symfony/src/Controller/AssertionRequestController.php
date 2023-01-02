<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Throwable;
use Webauthn\Bundle\CredentialOptionsBuilder\PublicKeyCredentialRequestOptionsBuilder;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Handler\RequestOptionsHandler;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;

final class AssertionRequestController
{
    public function __construct(
        private readonly PublicKeyCredentialRequestOptionsBuilder $optionsBuilder,
        private readonly OptionsStorage $optionsStorage,
        private readonly RequestOptionsHandler $optionsHandler,
        private readonly FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        try {
            $userEntity = null;
            $publicKeyCredentialRequestOptions = $this->optionsBuilder->getFromRequest($request, $userEntity);
            $response = $this->optionsHandler->onRequestOptions($publicKeyCredentialRequestOptions, $userEntity);
            $this->optionsStorage->store(Item::create($publicKeyCredentialRequestOptions, $userEntity));

            return $response;
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
