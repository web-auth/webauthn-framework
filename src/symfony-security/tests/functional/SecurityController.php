<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\SecurityBundle\Tests\Functional;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Twig\Environment;
use Webauthn\SecurityBundle\Security\WebauthnUtils;

final class SecurityController
{
    /**
     * @var Environment
     */
    private $twig;

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var WebauthnUtils
     */
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

    public function assertion(Request $request): Response
    {
        /** @var UserInterface $user */
        $user = $this->tokenStorage->getToken()->getUser();
        $publicKeyCredentialRequestOptions = $this->webauthnUtils->generateRequest($user);
        $request->getSession()->set('_webauthn.public_key_credential_request_options', $publicKeyCredentialRequestOptions);
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
