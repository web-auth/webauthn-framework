<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit;

use Matthias\SymfonyConfigTest\PhpUnit\ConfigurationTestCaseTrait;
use PHPUnit\Framework\TestCase;
use Webauthn\Bundle\DependencyInjection\Configuration;

/**
 * @internal
 */
final class ConfigurationTest extends TestCase
{
    use ConfigurationTestCaseTrait;

    protected function getConfiguration(): Configuration
    {
        return new Configuration('webauthn');
    }
}
