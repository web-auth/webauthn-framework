<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Controller;

final class DummyControllerFactory
{
    public function create(): DummyController
    {
        return new DummyController();
    }
}
