<?php

declare(strict_types=1);

namespace Webauthn\TokenBinding;

use Psr\Http\Message\ServerRequestInterface;

interface TokenBindingHandler
{
    public function check(TokenBinding $tokenBinding, ServerRequestInterface $request): void;
}
