<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Symfony\Component\HttpFoundation\Response;
use Twig\Environment;

final readonly class HomeController
{
    public function __construct(
        private Environment $twig,
    ) {
    }

    public function home(): Response
    {
        return new Response('Home');
    }

    public function login(): Response
    {
        $page = $this->twig->render('login.html.twig');

        return new Response($page);
    }
}
