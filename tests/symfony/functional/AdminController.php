<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Tests\Functional;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

final class AdminController
{
    public function __construct(private TokenStorageInterface $tokenStorage, private AuthorizationCheckerInterface $authorizationChecker)
    {
    }

    public function admin(): Response
    {
        $token = $this->tokenStorage->getToken();
        $user = $token->getUser();

        return new JsonResponse([
            'Hello '.$user->getUsername(),
        ]);
    }
}
