<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Exception;

use Throwable;

final class MetadataStatementLoadingException extends MetadataStatementException
{
    public static function create(string $message, ?Throwable $previous = null): self
    {
        return new self($message, $previous);
    }
}
