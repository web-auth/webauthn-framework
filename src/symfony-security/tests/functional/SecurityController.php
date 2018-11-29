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

namespace Webauthn\Security\Bundle\Tests\Functional;

use Symfony\Component\HttpFoundation\Response;

final class SecurityController
{
    public function login(): Response
    {
        return new Response('Login');
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
