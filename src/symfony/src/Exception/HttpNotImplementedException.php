<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Exception;

use Symfony\Component\HttpKernel\Exception\HttpException;
use Throwable;

class HttpNotImplementedException extends HttpException
{
    /**
     * @param array<string, mixed> $headers
     */
    public function __construct(string $message = '', ?Throwable $previous = null, int $code = 0, array $headers = [])
    {
        parent::__construct(501, $message, $previous, $headers, $code);
    }
}
