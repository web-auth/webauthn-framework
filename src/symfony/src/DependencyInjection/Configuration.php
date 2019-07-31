<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\ConformanceToolset\Controller\AttestationRequestController;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialSourceRepository;
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
        /** @var ArrayNodeDefinition $rootNode */
        $rootNode = $treeBuilder->getRootNode();

        $rootNode
            ->addDefaultsIfNotSet()
            ->children()
                ->scalarNode('credential_repository')
                    ->isRequired()
                    ->info('This repository is responsible of the credential storage')
                ->end()
                ->scalarNode('user_repository')
                    ->isRequired()
                    ->info('This repository is responsible of the user storage. It is mandatory when using the transport binding profile feature')
                ->end()
                ->scalarNode('token_binding_support_handler')
                    ->defaultValue(TokenBindingNotSupportedHandler::class)
                    ->cannotBeEmpty()
                    ->info('This handler will check the token binding header from the request')
                ->end()
                ->arrayNode('android_safetynet')
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('http_client')
                            ->isRequired()
                            ->info('HttpPlug Client')
                        ->end()
                        ->scalarNode('api_key')
                            ->isRequired()
                            ->info('API key from Google API and Services. See https://console.developers.google.com/apis/library to get it.')
                        ->end()
                    ->end()
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

        if (class_exists(AttestationRequestController::class)) {
            $this->appendTokenTransportBinding($rootNode);
        }

        return $treeBuilder;
    }

    private function appendTokenTransportBinding(ArrayNodeDefinition $node): void
    {
        $node->children()
            ->arrayNode('transport_binding_profile')
                ->treatFalseLike([])
                ->treatNullLike([])
                ->addDefaultsIfNotSet()
                ->children()
                    ->arrayNode('creation')
                        ->treatFalseLike([])
                        ->treatNullLike([])
                        ->useAttributeAsKey('name')
                        ->arrayPrototype()
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->scalarNode('profile_name')
                                    ->info('The name of the profile. Should be one of the creation profiles registered at path "webauthn.creation_profiles"')
                                    ->isRequired()
                                ->end()
                                ->scalarNode('user_entity_repository')
                                    ->info('User entity repository')
                                    ->defaultValue(PublicKeyCredentialUserEntityRepository::class)
                                ->end()
                                ->scalarNode('credential_source_repository')
                                    ->info('Public key credential source  repository')
                                    ->defaultValue(PublicKeyCredentialSourceRepository::class)
                                ->end()
                                ->scalarNode('request_path')
                                    ->info('The path of the creation request')
                                    ->isRequired()
                                ->end()
                                ->scalarNode('response_path')
                                    ->info('The path of the creation response')
                                    ->isRequired()
                                ->end()
                                ->scalarNode('session_parameter_name')
                                    ->info('The session name parameter')
                                    ->isRequired()
                                ->end()
                                ->scalarNode('host')
                                    ->info('The hostname')
                                    ->defaultNull()
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                    ->arrayNode('request')
                        ->treatFalseLike([])
                        ->treatNullLike([])
                        ->useAttributeAsKey('name')
                        ->arrayPrototype()
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->scalarNode('profile_name')
                                    ->info('The name of the profile. Shold be one of the creation profiles registered at path "webauthn.creation_profiles"')
                                    ->isRequired()
                                ->end()
                                ->scalarNode('user_entity_repository')
                                    ->info('User entity repository')
                                    ->defaultValue(PublicKeyCredentialUserEntityRepository::class)
                                ->end()
                                ->scalarNode('credential_source_repository')
                                    ->info('Public key credential source  repository')
                                    ->defaultValue(PublicKeyCredentialSourceRepository::class)
                                ->end()
                                ->scalarNode('request_path')
                                    ->info('The path of the creation request')
                                    ->isRequired()
                                ->end()
                                ->scalarNode('response_path')
                                    ->info('The path of the creation response')
                                    ->isRequired()
                                ->end()
                                ->scalarNode('session_parameter_name')
                                    ->info('The session name parameter')
                                    ->isRequired()
                                ->end()
                                ->scalarNode('host')
                                    ->info('The hostname')
                                    ->defaultNull()
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end()
        ->end();
    }
}
