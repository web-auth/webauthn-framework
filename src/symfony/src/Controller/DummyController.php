<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use RuntimeException;

final class DummyController
{
    public function __invoke(): void
    {
        throw new RuntimeException('This method should never be called.');
    }
}
