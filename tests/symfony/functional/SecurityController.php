<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

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
