<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
use Webauthn\Bundle\Security\Handler\FailureHandler;

final class DefaultFailureHandler implements FailureHandler
{
    public function onFailure(Request $request, ?Throwable $exception = null): Response
    {
        $data = [
            'status' => 'error',
            'errorMessage' => $exception === null ? 'An unexpected error occurred' : $exception->getMessage(),
        ];

        return new JsonResponse($data, Response::HTTP_BAD_REQUEST);
    }
}
