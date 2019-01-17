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

namespace Webauthn\Bundle\DependencyInjection;

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
        $treeBuilder = new TreeBuilder('webauthn');
        $rootNode = $treeBuilder->root($this->alias);

        $rootNode
            ->addDefaultsIfNotSet()
            ->children()
                ->scalarNode('credential_repository')
                    ->isRequired()
                    ->info('This repository is responsible of the credential storage')
                ->end()
                ->scalarNode('token_binding_support_handler')
                    ->defaultValue(TokenBindingNotSupportedHandler::class)
                    ->cannotBeEmpty()
                    ->info('This handler will check the token binding header from the request')
                ->end()
            ->end();

        return $treeBuilder;
    }
}
