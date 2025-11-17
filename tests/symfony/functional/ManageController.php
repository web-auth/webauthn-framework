<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

final readonly class ManageController
{
    public function manage(): Response
    {
        return new JsonResponse([
            'manage' => 'endpoint',
        ]);
    }
}
