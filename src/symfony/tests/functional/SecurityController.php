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

namespace Webauthn\Bundle\Tests\Functional;

use Symfony\Component\HttpFoundation\Response;

final class SecurityController
{
    /**
     * Intercepted by the security listener.
     */
    public function logout(): Response
    {
        return new Response('logout');
    }
}
