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

namespace Webauthn\Security\Bundle\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\Security\Bundle\Security\Authentication\Provider\WebauthnProvider;
use Webauthn\Security\Bundle\Security\EntryPoint\UsernameEntryPoint;
use Webauthn\Security\Bundle\Security\Firewall\WebauthnListener;

class WebauthnSecurityFactory implements SecurityFactoryInterface
{
    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $providerId = 'security.authentication.provider.webauthn.'.$id;
        $container
            ->setDefinition($providerId, new ChildDefinition(WebauthnProvider::class))
            ->setArgument(1, $id)
        ;

        $listenerId = 'security.authentication.listener.webauthn.'.$id;
        $container
            ->setDefinition($listenerId, new ChildDefinition(WebauthnListener::class))
            ->setArgument(3, $id)
            ->setArgument(4, $config)
        ;

        return [$providerId, $listenerId, $defaultEntryPoint];
    }

    public function getPosition()
    {
        return 'form';
    }

    public function getKey()
    {
        return 'webauthn';
    }

    public function addConfiguration(NodeDefinition $node)
    {
        $supportedUserVerificationModes = [
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        ];

        /* @var ArrayNodeDefinition $node */
        $node
            ->addDefaultsIfNotSet()
            ->children()
                ->scalarNode('login_path')
                    ->info('Login path.')
                    ->defaultValue('/login')
                ->end()
                ->scalarNode('check_path')
                    ->info('Check path.')
                    ->defaultValue('/login_check')
                ->end()
                ->arrayNode('relaying_party')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('rpId')
                            ->info('The relaying Party ID (rpId) corresponds to the domain or subdomain of the application. Scheme, port and other URI components shall be avoided. Ex.: "https://foo.bar.com" => "foo.bar.com" or "bar.com".')
                            ->defaultNull()
                        ->end()
                        ->scalarNode('name')
                            ->info('The relaying Party name. This name may be displayed by the browser')
                            ->defaultValue('Webauthn Security')
                        ->end()
                        ->scalarNode('icon')
                            ->info('The relaying Party icon. This name may be displayed by the browser')
                            ->defaultNull()
                        ->end()
                    ->end()
                ->end()
                ->integerNode('timeout')
                    ->info('Timeout before the end of interaction with the user. May be ignored by the browser.')
                    ->defaultValue(60000)
                    ->min(0)
                ->end()
                ->integerNode('challenge_length')
                    ->info('Length of the challenge. This length should not be lower than 32 bytes.')
                    ->defaultValue(32)
                    ->min(1)
                ->end()
                ->scalarNode('user_verification')
                    ->info('Indicates if the user has to be verified. Only devices supporting this feature will be able to interact with the user.')
                    ->defaultValue(PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED)
                    ->validate()
                        ->ifNotInArray($supportedUserVerificationModes)
                        ->thenInvalid('Unsupported user verification mode. Possible values are: '.implode(', ', $supportedUserVerificationModes))
                    ->end()
                ->end()
            ->end();
    }

    private function createUsernameEntryPoint(ContainerBuilder $container, string $id, array $config)
    {
        $entryPointId = 'webauthn.security.authentication.username_entry_point.'.$id;
        $container
            ->setDefinition($entryPointId, new ChildDefinition(UsernameEntryPoint::class))
            ->addArgument(new Reference('security.http_utils'))
            ->addArgument($config['login_path'])
            ->addArgument($config['use_forward'])
        ;

        return $entryPointId;
    }
}
