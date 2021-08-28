<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection;

use Cose\Algorithms;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialSourceRepository;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Handler\DefaultCreationOptionsHandler;
use Webauthn\Bundle\Security\Storage\SessionStorage;
use Webauthn\Bundle\Service\DefaultFailureHandler;
use Webauthn\Bundle\Service\DefaultSuccessHandler;
use Webauthn\ConformanceToolset\Controller\AttestationRequestController;
use Webauthn\Counter\ThrowExceptionIfInvalid;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;

final class Configuration implements ConfigurationInterface
{
    public function __construct(private string $alias)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder($this->alias);
        /** @var ArrayNodeDefinition $rootNode */
        $rootNode = $treeBuilder->getRootNode();

        $rootNode
            ->addDefaultsIfNotSet()
            ->beforeNormalization()
            ->ifArray()
            ->then(static function ($v): array {
                if (!isset($v['creation_profiles'])) {
                    $v['creation_profiles'] = null;
                }
                if (!isset($v['request_profiles'])) {
                    $v['request_profiles'] = null;
                }

                return $v;
            })
            ->end()
            ->children()
            ->scalarNode('logger')
            ->defaultNull()
            ->info('A PSR3 logger to receive logs during the processes')
            ->end()
            ->scalarNode('credential_repository')
            ->cannotBeEmpty()
            ->defaultValue(DummyPublicKeyCredentialSourceRepository::class)
            ->info('This repository is responsible of the credential storage')
            ->end()
            ->scalarNode('user_repository')
            ->cannotBeEmpty()
            ->defaultValue(DummyPublicKeyCredentialUserEntityRepository::class)
            ->info('This repository is responsible of the user storage')
            ->end()
            ->scalarNode('token_binding_support_handler')
            ->defaultValue(IgnoreTokenBindingHandler::class)
            ->cannotBeEmpty()
            ->info('This handler will check the token binding header from the request')
            ->end()
            ->scalarNode('counter_checker')
            ->defaultValue(ThrowExceptionIfInvalid::class)
            ->cannotBeEmpty()
            ->info('This service will check if the counter is valid. By default it throws an exception (recommended)')
            ->end()
            ->arrayNode('android_safetynet')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('http_client')
            ->defaultNull()
            ->info('PSR18 Client. If set, the application will verify the statements using Google API. See https://console.developers.google.com/apis/library to get it.')
            ->end()
            ->scalarNode('request_factory')
            ->defaultNull()
            ->info('PSR17 Request Factory. If set, the application will verify the statements using Google API. See https://console.developers.google.com/apis/library to get it.')
            ->end()
            ->integerNode('leeway')
            ->defaultValue(0)
            ->min(0)
            ->info('Leeway for timestamp verification in response (in millisecond). At least 2000 msec are recommended.')
            ->end()
            ->integerNode('max_age')
            ->min(0)
            ->defaultValue(60000)
            ->info('Maximum age of the response (in millisecond)')
            ->end()
            ->scalarNode('api_key')
            ->defaultNull()
            ->info('If set, the application will verify the statements using Google API. See https://console.developers.google.com/apis/library to get it.')
            ->end()
            ->end()
            ->end()
            ->arrayNode('certificate_chain_checker')
            ->canBeEnabled()
            ->children()
            ->scalarNode('http_client')
            ->isRequired()
            ->info('PSR18 Client.')
            ->end()
            ->scalarNode('request_factory')
            ->isRequired()
            ->info('PSR17 Request Factory.')
            ->end()
            ->end()
            ->end()
            ->arrayNode('metadata_service')
            ->canBeEnabled()
            ->children()
            ->scalarNode('repository')
            ->isRequired()
            ->info('Metadata Statement repository')
            ->end()
            ->end()
            ->end()
            ->arrayNode('controllers')
            ->canBeEnabled()
            ->children()
            ->arrayNode('creation')
            ->treatFalseLike([])
            ->treatNullLike([])
            ->treatTrueLike([])
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('options_path')->isRequired()->end()
            ->scalarNode('result_path')->isRequired()->end()
            ->scalarNode('host')->defaultValue(null)->end()
            ->scalarNode('profile')->defaultValue('default')->end()
            ->scalarNode('user_entity_guesser')->isRequired()->end()
            ->scalarNode('options_storage')->defaultValue(SessionStorage::class)->end()
            ->scalarNode('success_handler')->defaultValue(DefaultSuccessHandler::class)->end()
            ->scalarNode('failure_handler')->defaultValue(DefaultFailureHandler::class)->end()
            ->scalarNode('options_handler')->defaultValue(DefaultCreationOptionsHandler::class)->end()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
            ->arrayNode('creation_profiles')
            ->treatFalseLike(['default' => ['rp' => ['name' => 'Secured Application']]])
            ->treatNullLike(['default' => ['rp' => ['name' => 'Secured Application']]])
            ->treatTrueLike(['default' => ['rp' => ['name' => 'Secured Application']]])
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
            ->scalarNode('attachment_mode')
            ->defaultValue(AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE)
            ->validate()
            ->ifNotInArray([
                AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
                AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
                AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            ])
            ->thenInvalid('Invalid value "%s"')
            ->end()
            ->end()
            ->booleanNode('require_resident_key')->defaultFalse()->end()
            ->scalarNode('user_verification')
            ->defaultValue(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED)
            ->validate()
            ->ifNotInArray([
                AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
                AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            ])
            ->thenInvalid('Invalid value "%s"')
            ->end()
            ->end()
            ->scalarNode('resident_key')
            ->defaultValue(AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NONE)
            ->validate()
            ->ifNotInArray([
                AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NONE,
                AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_DISCOURAGED,
                AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
                AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ])
            ->thenInvalid('Invalid value "%s"')
            ->end()
            ->end()
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
            ->integerPrototype()->end()
            ->requiresAtLeastOneElement()
            ->treatNullLike([])
            ->treatFalseLike([])
            ->treatTrueLike([])
            ->defaultValue([
                Algorithms::COSE_ALGORITHM_EdDSA,
                Algorithms::COSE_ALGORITHM_ES256,
                Algorithms::COSE_ALGORITHM_ES256K,
                Algorithms::COSE_ALGORITHM_ES384,
                Algorithms::COSE_ALGORITHM_ES512,
                Algorithms::COSE_ALGORITHM_RS256,
                Algorithms::COSE_ALGORITHM_RS384,
                Algorithms::COSE_ALGORITHM_RS512,
                Algorithms::COSE_ALGORITHM_PS256,
                Algorithms::COSE_ALGORITHM_PS384,
                Algorithms::COSE_ALGORITHM_PS512,
            ])
            ->end()
            ->scalarNode('attestation_conveyance')
            ->defaultValue(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE)
            ->end()
            ->end()
            ->end()
            ->end()
            ->arrayNode('request_profiles')
            ->treatFalseLike(['default' => []])
            ->treatTrueLike(['default' => []])
            ->treatNullLike(['default' => []])
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
            ->end()
        ;

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
            ->info('The name of the profile. Should be one of the creation profiles registered at path "webauthn.creation_profiles"')
            ->isRequired()
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
            ->end()
        ;
    }
}
