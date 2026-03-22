<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\Bundle\Controller\PasskeyEndpointsController;
use Webauthn\Bundle\Routing\Loader;
use Webauthn\PasskeyEndpointsResponse;
use Webauthn\Url;

/**
 * Compiler pass to register the .well-known/passkey-endpoints controller and route.
 *
 * @see https://w3c.github.io/webappsec-passkey-endpoints/
 */
final class PasskeyEndpointsCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasParameter('webauthn.passkey_endpoints.enabled')) {
            return;
        }

        $enabled = $container->getParameter('webauthn.passkey_endpoints.enabled');
        if ($enabled !== true) {
            return;
        }

        $this->createPasskeyEndpointsResponse($container);
        $this->createControllerDefinition($container);
    }

    private function createPasskeyEndpointsResponse(ContainerBuilder $container): void
    {
        /** @var string|array<string, mixed>|null $enroll */
        $enroll = $container->getParameter('webauthn.passkey_endpoints.enroll');
        /** @var string|array<string, mixed>|null $manage */
        $manage = $container->getParameter('webauthn.passkey_endpoints.manage');
        /** @var string|array<string, mixed>|null $prfUsageDetails */
        $prfUsageDetails = $container->getParameter('webauthn.passkey_endpoints.prf_usage_details');

        // Create Url definitions from string configuration
        $enrollUrl = $enroll !== null ? $this->createUrlDefinition($enroll) : null;
        $manageUrl = $manage !== null ? $this->createUrlDefinition($manage) : null;
        $prfUrl = $prfUsageDetails !== null ? $this->createUrlDefinition($prfUsageDetails) : null;

        $responseDefinition = new Definition(PasskeyEndpointsResponse::class, [$enrollUrl, $manageUrl, $prfUrl]);

        $container->setDefinition(PasskeyEndpointsResponse::class, $responseDefinition);
    }

    /**
     * Creates a Url definition from configuration value (string or array) using the serializer to denormalize it.
     *
     * @param string|array<string, mixed> $value
     */
    private function createUrlDefinition(string|array $value): Definition
    {
        $urlDefinition = new Definition(Url::class);
        $urlDefinition->setFactory([new Reference(SerializerInterface::class), 'denormalize']);
        $urlDefinition->setArguments([$value, Url::class, 'json']);

        return $urlDefinition;
    }

    private function createControllerDefinition(ContainerBuilder $container): void
    {
        if (! $container->hasDefinition(Loader::class)) {
            return;
        }

        if (! $container->hasDefinition(PasskeyEndpointsResponse::class)) {
            return;
        }

        $controllerDefinition = new Definition(
            PasskeyEndpointsController::class,
            [$container->getDefinition(PasskeyEndpointsResponse::class), new Reference(SerializerInterface::class)]
        );
        $controllerDefinition->setPublic(true);

        $container->setDefinition(PasskeyEndpointsController::class, $controllerDefinition);

        $loaderDefinition = $container->getDefinition(Loader::class);
        $loaderDefinition->addMethodCall('add', [
            '/.well-known/passkey-endpoints',
            null,
            PasskeyEndpointsController::class,
            'GET',
        ]);
    }
}
