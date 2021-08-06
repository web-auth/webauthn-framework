<?php

declare(strict_types=1);

namespace Webauthn\TokenBinding;

use JetBrains\PhpStorm\Pure;
use Psr\Http\Message\ServerRequestInterface;

final class IgnoreTokenBindingHandler implements TokenBindingHandler
{
    #[Pure]
    public static function create(): self
    {
        return new self();
    }

    #[Pure]
    public function check(TokenBinding $tokenBinding, ServerRequestInterface $request): void
    {
        //Does nothing
    }
}
