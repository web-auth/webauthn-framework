<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional\ServiceDefinition;

use Matthias\SymfonyDependencyInjectionTest\PhpUnit\AbstractExtensionTestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\Bundle\DependencyInjection\WebauthnExtension;

/**
 * @internal
 */
final class OptionsBuilderParameterTest extends AbstractExtensionTestCase
{
    #[Test]
    public function theDefaultOptionsBuilderIsUsedWhenNoOptionIsSet(): void
    {
        // When
        $this->load([
            'clock' => 'system',
            'controllers' => [
                'creation' => [
                    'creation_111' => [
                        'options_path' => '/foo/creation/options',
                        'result_path' => '/foo/creation',
                        'user_entity_guesser' => 'custom.user_entity_guesser',
                        'profile' => 'foo',
                    ],
                ],
                'request' => [
                    'request_222' => [
                        'options_path' => '/bar/request/options',
                        'result_path' => '/bar/request',
                        'profile' => 'bar',
                    ],
                ],
            ],
        ]);

        // Then
        $this->assertContainerBuilderHasServiceDefinitionWithArgument(
            'webauthn.controller.request.options_builder.request_222',
            5,
            'bar'
        );
        $this->assertContainerBuilderHasServiceDefinitionWithArgument(
            'webauthn.controller.creation.options_builder.creation_111',
            4,
            'foo'
        );

        $this->assertContainerBuilderHasServiceDefinitionWithArgument(
            'webauthn.controller.request.request.request_222',
            0,
            new Reference('webauthn.controller.request.options_builder.request_222')
        );
        $this->assertContainerBuilderHasServiceDefinitionWithArgument(
            'webauthn.controller.creation.request.creation_111',
            0,
            new Reference('webauthn.controller.creation.options_builder.creation_111')
        );
    }

    #[Test]
    public function aCustomOptionsBuilderCanBeSet(): void
    {
        // When
        $this->load([
            'clock' => 'system',
            'controllers' => [
                'creation' => [
                    'creation_111' => [
                        'options_path' => '/foo/creation/options',
                        'result_path' => '/foo/creation',
                        'options_builder' => 'custom_creation_options_builder_1',
                        'user_entity_guesser' => 'custom.user_entity_guesser',
                        'profile' => 'foo',
                    ],
                ],
                'request' => [
                    'request_222' => [
                        'options_path' => '/bar/request/options',
                        'result_path' => '/bar/request',
                        'options_builder' => 'custom_request_options_builder_2',
                        'profile' => 'bar',
                    ],
                ],
            ],
        ]);

        // Then
        $this->assertContainerBuilderNotHasService('webauthn.controller.request.options_builder.request_222');
        $this->assertContainerBuilderNotHasService('webauthn.controller.creation.options_builder.creation_111');

        $this->assertContainerBuilderHasServiceDefinitionWithArgument(
            'webauthn.controller.request.request.request_222',
            0,
            new Reference('custom_request_options_builder_2')
        );
        $this->assertContainerBuilderHasServiceDefinitionWithArgument(
            'webauthn.controller.creation.request.creation_111',
            0,
            new Reference('custom_creation_options_builder_1')
        );
    }

    protected function getContainerExtensions(): array
    {
        return [new WebauthnExtension('webauthn')];
    }
}
