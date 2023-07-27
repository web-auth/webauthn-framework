<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use LogicException;

final class DummyController
{
    public function __invoke(): never
    {
        throw new LogicException('This method should never be called.');
    }
}
