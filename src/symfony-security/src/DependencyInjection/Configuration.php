<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\SecurityBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;

final class Configuration implements ConfigurationInterface
{
    /**
     * @var string
     */
    private $alias;

    public function __construct(string $alias)
    {
        $this->alias = $alias;
    }

    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder('webauthn_security');
        $rootNode = $treeBuilder->root($this->alias);

        $rootNode
            ->addDefaultsIfNotSet()
            ->children()
                ->scalarNode('http_message_factory')
                    ->isRequired()
                    ->info('Converts Symfony Requests into PSR7 Requests. Must implement Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface.')
                ->end()
            ->end();

        return $treeBuilder;
    }
}
