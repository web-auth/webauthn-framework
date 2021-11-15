<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Tests\Functional;

use Symfony\Component\HttpFoundation\Response;

final class HomeController
{
    public function home(): Response
    {
        return new Response('Home');
    }
}
