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
use Symfony\Component\Security\Core\User\UserInterface;
use Twig\Environment;
use Webauthn\Bundle\Security\WebauthnUtils;

final class SecurityController
{
    private $twig;
    private $tokenStorage;
    private $webauthnUtils;

    public function __construct(Environment $twig, TokenStorageInterface $tokenStorage, WebauthnUtils $webauthnUtils)
    {
        $this->twig = $twig;
        $this->tokenStorage = $tokenStorage;
        $this->webauthnUtils = $webauthnUtils;
    }

    public function login(): Response
    {
        $error = $this->webauthnUtils->getLastAuthenticationError();
        $lastUsername = $this->webauthnUtils->getLastUsername();

        $page = $this->twig->render('login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);

        return new Response($page);
    }

    public function assertion(): Response
    {
        /** @var UserInterface $user */
        $user = $this->tokenStorage->getToken()->getUser();
        $publicKeyCredentialRequestOptions = $this->webauthnUtils->generateRequestFor($user);
        $error = $this->webauthnUtils->getLastAuthenticationError();

        $page = $this->twig->render('assertion.html.twig', [
            'error' => $error,
            'user' => $user,
            'publicKeyCredentialRequestOptions' => $publicKeyCredentialRequestOptions,
        ]);

        return new Response($page);
    }

    public function abort(): Response
    {
        return new Response('Abort');
    }

    public function logout(): Response
    {
        return new Response('Logout');
    }
}
