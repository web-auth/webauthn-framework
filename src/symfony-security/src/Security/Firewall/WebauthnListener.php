<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Security\Bundle\Security\Firewall;

use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\PropertyAccess\Exception\AccessException;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\PropertyAccess\PropertyAccessorInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Webauthn\Security\Bundle\Security\Authentication\Token\WebauthnToken;

class WebauthnListener implements ListenerInterface
{
    private $tokenStorage;
    private $authenticationManager;
    private $httpUtils;
    private $providerKey;
    private $propertyAccessor;
    private $options;

    public function __construct(TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, HttpUtils $httpUtils, string $providerKey, array $options, PropertyAccessorInterface $propertyAccessor = null)
    {
        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->httpUtils = $httpUtils;
        $this->providerKey = $providerKey;
        $this->propertyAccessor = $propertyAccessor ?: PropertyAccess::createPropertyAccessor();
        $this->options = $options;
    }

    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        if (false === mb_strpos($request->getRequestFormat(), 'json') && false === mb_strpos($request->getContentType() ?? '', 'json')) {
            return;
        }
        $data = json_decode($request->getContent());

        /*try {
            if (!$data instanceof \stdClass) {
                throw new BadRequestHttpException('Invalid JSON.');
            }

            try {
                $username = $this->propertyAccessor->getValue($data, $this->options['username_path']);
            } catch (AccessException $e) {
                throw new BadRequestHttpException(sprintf('The key "%s" must be provided.', $this->options['username_path']), $e);
            }

            if (!\is_string($username)) {
                throw new BadRequestHttpException(sprintf('The key "%s" must be a string.', $this->options['username_path']));
            }

            if (\mb_strlen($username) > Security::MAX_USERNAME_LENGTH) {
                throw new BadCredentialsException('Invalid username.');
            }

            $token = new WebauthnToken($username, $credentials, $this->providerKey);

            $authenticatedToken = $this->authenticationManager->authenticate($token);
            $response = $this->onSuccess($request, $authenticatedToken);
        } catch (AuthenticationException $e) {
            $response = $this->onFailure($request, $e);
        } catch (BadRequestHttpException $e) {
            $request->setRequestFormat('json');

            throw $e;
        }

        if (null === $response) {
            return;
        }

        $event->setResponse($response);*/
    }
}
