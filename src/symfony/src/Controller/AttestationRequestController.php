<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Throwable;
use Webauthn\Bundle\CredentialOptionsBuilder\PublicKeyCredentialCreationOptionsBuilder;
use Webauthn\Bundle\Security\Guesser\UserEntityGuesser;
use Webauthn\Bundle\Security\Handler\CreationOptionsHandler;
use Webauthn\Bundle\Security\Handler\FailureHandler;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\Bundle\Security\Storage\OptionsStorage;

final class AttestationRequestController
{
    public function __construct(
        private readonly PublicKeyCredentialCreationOptionsBuilder $extractor,
        private readonly UserEntityGuesser $userEntityGuesser,
        private readonly OptionsStorage $optionsStorage,
        private readonly CreationOptionsHandler $creationOptionsHandler,
        private readonly FailureHandler|AuthenticationFailureHandlerInterface $failureHandler,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        try {
            $userEntity = $this->userEntityGuesser->findUserEntity($request);
            $publicKeyCredentialCreationOptions = $this->extractor->getFromRequest($request, $userEntity);

            $response = $this->creationOptionsHandler->onCreationOptions(
                $publicKeyCredentialCreationOptions,
                $userEntity
            );
            $this->optionsStorage->store(Item::create($publicKeyCredentialCreationOptions, $userEntity));

            return $response;
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
