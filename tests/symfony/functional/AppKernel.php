<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Functional;

use Doctrine\Bundle\DoctrineBundle\DoctrineBundle;
use SpomkyLabs\CborBundle\SpomkyLabsCborBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\MonologBundle\MonologBundle;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\HttpKernel\Kernel;
use Webauthn\Bundle\WebauthnBundle;
use Webauthn\Stimulus\WebauthnStimulusBundle;

final class AppKernel extends Kernel
{
    /**
     * {@inheritdoc}
     */
    public function __construct(string $environment)
    {
        parent::__construct($environment, true);
    }

    /**
     * {@inheritdoc}
     */
    public function registerBundles(): iterable
    {
        return [
            new FrameworkBundle(),
            new SpomkyLabsCborBundle(),
            new DoctrineBundle(),
            new SecurityBundle(),
            new MonologBundle(),

            new WebauthnBundle(),
            new WebauthnStimulusBundle(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(__DIR__ . '/../config/config.yml');
    }
}
