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

namespace Webauthn\Bundle\Service;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
use Webauthn\Bundle\Security\Handler\FailureHandler;

final class DefaultFailureHandler implements FailureHandler
{
    public function onFailure(Request $request, Throwable $exception = null): Response
    {
        $data = [
            'status' => 'failed',
            'errorMessage' => $exception ? $exception->getMessage() : 'An unexpected error occurred',
        ];

        return new JsonResponse($data, Response::HTTP_BAD_REQUEST);
    }
}
