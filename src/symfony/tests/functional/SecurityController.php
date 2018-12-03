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

namespace Webauthn\Bundle\Tests\Functional;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Twig\Environment;
use Webauthn\Bundle\Security\Authentication\Token\PreWebauthnToken;

final class SecurityController
{
    private $twig;
    private $tokenStorage;
    private $authenticationUtils;

    public function __construct(Environment $twig, TokenStorageInterface $tokenStorage, AuthenticationUtils $authenticationUtils)
    {
        $this->twig = $twig;
        $this->tokenStorage = $tokenStorage;
        $this->authenticationUtils = $authenticationUtils;
    }

    public function login(): Response
    {
        $error = $this->authenticationUtils->getLastAuthenticationError();
        $lastUsername = $this->authenticationUtils->getLastUsername();

        $page = $this->twig->render('login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);

        return new Response($page);
    }

    public function assertion(): Response
    {
        /** @var PreWebauthnToken $token */
        $token = $this->tokenStorage->getToken();
        $error = $this->authenticationUtils->getLastAuthenticationError();

        $page = $this->twig->render('assertion.html.twig', [
            'error' => $error,
            'publicKeyCredentialRequestOptions' => $token->getCredentials(),
        ]);

        return new Response($page);
    }

    public function check(): Response
    {
        return new Response('Check');
    }

    public function logout(): Response
    {
        return new Response('Logout');
    }
}
