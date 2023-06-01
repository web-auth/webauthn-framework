<?php

declare(strict_types=1);

namespace Webauthn\Stimulus;

use function dirname;

use Symfony\Component\HttpKernel\Bundle\Bundle;

final class StimulusBundle extends Bundle
{
    public function getPath(): string
    {
        return dirname(__DIR__);
    }
}
