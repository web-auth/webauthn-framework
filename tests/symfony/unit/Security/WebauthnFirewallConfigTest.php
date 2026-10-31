<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Security;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Http\HttpUtils;
use Webauthn\Bundle\DependencyInjection\Factory\Security\WebauthnFactory;
use Webauthn\Bundle\Security\WebauthnFirewallConfig;

final class WebauthnFirewallConfigTest extends TestCase
{
    #[Test]
    public function theFailureHandlerIsReadFromTheFailureHandlerOption(): void
    {
        $config = new WebauthnFirewallConfig([
            'success_handler' => 'app.success_handler',
            'failure_handler' => 'app.failure_handler',
        ], 'main', new HttpUtils());

        static::assertSame('app.failure_handler', $config->getFailureHandler());
    }

    #[Test]
    public function theFailureHandlerDefaultsToTheDefaultFailureHandlerWhenOnlyTheSuccessHandlerIsSet(): void
    {
        $config = new WebauthnFirewallConfig([
            'success_handler' => 'app.success_handler',
        ], 'main', new HttpUtils());

        static::assertSame(WebauthnFactory::DEFAULT_FAILURE_HANDLER_SERVICE, $config->getFailureHandler());
    }

    #[Test]
    public function theRegistrationOptionsHandlerDefaultsToTheCreationOptionsHandler(): void
    {
        $config = new WebauthnFirewallConfig([], 'main', new HttpUtils());

        static::assertSame(
            WebauthnFactory::DEFAULT_CREATION_OPTIONS_HANDLER_SERVICE,
            $config->getRegistrationOptionsHandler()
        );
    }
}
