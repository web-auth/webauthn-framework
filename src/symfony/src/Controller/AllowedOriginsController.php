<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;

final readonly class AllowedOriginsController
{
    /**
     * @param string[] $allowedOrigins
     */
    public function __construct(
        private array $allowedOrigins
    ) {
    }

    public function __invoke(): JsonResponse
    {
        return new JsonResponse([
            'origins' => $this->allowedOrigins,
        ]);
    }
}
