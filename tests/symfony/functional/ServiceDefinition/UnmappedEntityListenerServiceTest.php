<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\ServiceDefinition;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractExtensionTestCase;
use PHPUnit\Framework\Attributes\Test;
use Webauthn\Bundle\DependencyInjection\WebauthnExtension;
use Webauthn\Bundle\Doctrine\UnmappedEntityListener;

/**
 * @internal
 */
final class UnmappedEntityListenerServiceTest extends AbstractExtensionTestCase
{
    /**
     * The listener refuses the entities expecting the Doctrine mapping removed in 6.0.0. It has to be called whenever
     * Doctrine loads the metadata of an entity.
     *
     * @see https://github.com/web-auth/webauthn-framework/issues/1007
     */
    #[Test]
    public function theListenerIsRegisteredForTheLoadingOfTheMetadata(): void
    {
        // When
        $this->load([
            'clock' => 'system',
        ]);

        // Then
        $this->assertContainerBuilderHasServiceDefinitionWithTag(
            UnmappedEntityListener::class,
            'doctrine.event_listener',
            [
                'event' => 'loadClassMetadata',
            ]
        );
    }

    protected function getContainerExtensions(): array
    {
        return [new WebauthnExtension('webauthn')];
    }
}
