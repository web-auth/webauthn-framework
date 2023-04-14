<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Exception;

use Throwable;
use Webauthn\Exception\WebauthnException;

final class MissingFeatureException extends WebauthnException
{
    public static function create(string $message, ?Throwable $previous = null): self
    {
        return new self($message, $previous);
    }
}
