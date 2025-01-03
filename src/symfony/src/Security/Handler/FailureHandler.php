<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Handler;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

interface FailureHandler
{
    public function onFailure(Request $request, ?Throwable $exception = null): Response;
}
