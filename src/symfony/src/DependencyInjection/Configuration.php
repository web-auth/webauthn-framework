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

use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
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
        $treeBuilder = new TreeBuilder($this->alias);
        $rootNode = $this->getRootNode($treeBuilder, $this->alias);

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
                ->arrayNode('creation_profiles')
                    ->treatFalseLike([])
                    ->treatNullLike([])
                    ->useAttributeAsKey('name')
                    ->arrayPrototype()
                        ->addDefaultsIfNotSet()
                        ->children()
                            ->arrayNode('rp')
                                ->isRequired()
                                ->children()
                                    ->scalarNode('id')->defaultNull()->end()
                                    ->scalarNode('name')->isRequired()->end()
                                    ->scalarNode('icon')->defaultNull()->end()
                                ->end()
                            ->end()
                            ->integerNode('challenge_length')
                                ->min(16)
                                ->defaultValue(32)
                            ->end()
                            ->integerNode('timeout')
                                ->min(0)
                                ->defaultValue(60000)
                            ->end()
                            ->arrayNode('authenticator_selection_criteria')
                                ->addDefaultsIfNotSet()
                                ->children()
                                    ->scalarNode('attachment_mode')->defaultValue(AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE)->end()
                                    ->booleanNode('require_resident_key')->defaultFalse()->end()
                                    ->scalarNode('user_verification')->defaultValue(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED)->end()
                                ->end()
                            ->end()
                            ->arrayNode('extensions')
                                ->treatFalseLike([])
                                ->treatTrueLike([])
                                ->treatNullLike([])
                                ->useAttributeAsKey('name')
                                ->scalarPrototype()->end()
                            ->end()
                            ->arrayNode('public_key_credential_parameters')
                                ->variablePrototype()->end()
                                ->isRequired()
                                ->requiresAtLeastOneElement()
                            ->end()
                            ->scalarNode('attestation_conveyance')
                                ->defaultValue(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE)
                            ->end()
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('request_profiles')
                    ->treatFalseLike([])
                    ->treatNullLike([])
                    ->useAttributeAsKey('name')
                    ->arrayPrototype()
                        ->addDefaultsIfNotSet()
                        ->children()
                            ->scalarNode('rp_id')->defaultNull()->end()
                            ->integerNode('challenge_length')
                                ->min(16)
                                ->defaultValue(32)
                            ->end()
                            ->integerNode('timeout')
                                ->min(0)
                                ->defaultValue(60000)
                            ->end()
                            ->scalarNode('user_verification')->defaultValue(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED)->end()
                            ->arrayNode('extensions')
                                ->treatFalseLike([])
                                ->treatTrueLike([])
                                ->treatNullLike([])
                                ->useAttributeAsKey('name')
                                ->scalarPrototype()->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }

    private function getRootNode(TreeBuilder $treeBuilder, string $name): NodeDefinition
    {
        if (!\method_exists($treeBuilder, 'getRootNode')) {
            return $treeBuilder->root($name);
        }

        return $treeBuilder->getRootNode();
    }
}
