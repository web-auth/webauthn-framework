<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Security\Handler;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;

final class DefaultSuccessHandler implements SuccessHandler, AuthenticationSuccessHandlerInterface
{
    public function onSuccess(Request $request): Response
    {
        $data = [
            'status' => 'ok',
            'errorMessage' => '',
        ];

        return new JsonResponse($data, JsonResponse::HTTP_OK);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token): Response
    {
        return $this->onSuccess($request);
    }
}
