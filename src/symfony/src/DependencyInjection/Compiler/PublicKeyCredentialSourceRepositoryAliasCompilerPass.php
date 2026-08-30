<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection\Compiler;

use function class_exists;
use function is_string;
use function is_subclass_of;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Webauthn\Bundle\Repository\PublicKeyCredentialSourceRepositoryInterface;

/**
 * The bundle aliases the deprecated PublicKeyCredentialSourceRepositoryInterface to the configured credential
 * repository, so that applications still type-hinting that interface keep working. Symfony rejects an alias on an
 * interface when the target class does not implement it, hence the alias is dropped when the configured repository
 * only implements CredentialRecordRepositoryInterface. When the target class cannot be determined, the alias is left
 * untouched: Symfony does not validate such aliases either.
 *
 * This pass will be removed in 6.0, together with PublicKeyCredentialSourceRepositoryInterface.
 */
final class PublicKeyCredentialSourceRepositoryAliasCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (! $container->hasAlias(PublicKeyCredentialSourceRepositoryInterface::class)) {
            return;
        }

        $target = (string) $container->getAlias(PublicKeyCredentialSourceRepositoryInterface::class);
        $class = $this->getTargetClass($container, $target);
        if ($class === null || is_subclass_of($class, PublicKeyCredentialSourceRepositoryInterface::class)) {
            return;
        }

        $container->removeAlias(PublicKeyCredentialSourceRepositoryInterface::class);
    }

    private function getTargetClass(ContainerBuilder $container, string $id): ?string
    {
        $visited = [];
        while ($container->hasAlias($id)) {
            if (isset($visited[$id])) {
                return null;
            }
            $visited[$id] = true;
            $id = (string) $container->getAlias($id);
        }

        if (! $container->hasDefinition($id)) {
            return null;
        }

        $definition = $container->getDefinition($id);
        if ($definition->getFactory() !== null) {
            return null;
        }

        $class = $definition->getClass() ?? $id;
        $class = $container->getParameterBag()
            ->resolveValue($class);

        return is_string($class) && class_exists($class) ? $class : null;
    }
}
