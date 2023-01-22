<?php

declare(strict_types=1);

namespace Webauthn\Tests;

use PHPUnit\Framework\MockObject\MockObject;

trait MockedRequestTrait
{
    abstract protected function createMock(string $originalClassName): MockObject;
}
