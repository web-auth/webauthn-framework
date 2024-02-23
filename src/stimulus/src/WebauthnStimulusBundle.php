<?php

declare(strict_types=1);

namespace Webauthn\Stimulus;

use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Webauthn\Stimulus\DependencyInjection\WebauthnStimulusExtension;
use function dirname;

final class WebauthnStimulusBundle extends Bundle
{
    public function getContainerExtension(): ?ExtensionInterface
    {
        return new WebauthnStimulusExtension();
    }

    public function getPath(): string
    {
        return dirname(__DIR__);
    }
}
