<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

use JetBrains\PhpStorm\Pure;

final class DummyControllerFactory
{
    #[Pure]
    public function create(): DummyController
    {
        return new DummyController();
    }
}
