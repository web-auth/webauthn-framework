<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions;

use Exception;
use JetBrains\PhpStorm\Pure;
use Throwable;

class ExtensionOutputError extends Exception
{
    #[Pure]
    public function __construct(private AuthenticationExtension $authenticationExtension, string $message = '', int $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    #[Pure]
    public function getAuthenticationExtension(): AuthenticationExtension
    {
        return $this->authenticationExtension;
    }
}
