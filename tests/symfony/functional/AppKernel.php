<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Composer\InstalledVersions;
use Composer\Semver\VersionParser;
use Doctrine\Bundle\DoctrineBundle\DoctrineBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\MonologBundle\MonologBundle;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\HttpKernel\Kernel;
use Webauthn\Bundle\WebauthnBundle;
use Webauthn\Stimulus\WebauthnStimulusBundle;

final class AppKernel extends Kernel
{
    public function __construct(string $environment)
    {
        parent::__construct($environment, true);
    }

    public function registerBundles(): iterable
    {
        return [
            new FrameworkBundle(),
            new DoctrineBundle(),
            new SecurityBundle(),
            new MonologBundle(),
            new TwigBundle(),

            new WebauthnBundle(),
            new WebauthnStimulusBundle(),
        ];
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(__DIR__ . '/../config/config.yml');

        $loader->load(function ($container) {
            $isDoctrineBundle2 = InstalledVersions::satisfies(
                new VersionParser(),
                'doctrine/doctrine-bundle',
                '^2.0'
            );

            if ($isDoctrineBundle2) {
                $container->loadFromExtension('doctrine', [
                    'orm' => [
                        'enable_lazy_ghost_objects' => true,
                        'auto_generate_proxy_classes' => true,
                    ],
                ]);
            }
        });
    }
}
