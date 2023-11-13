<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection;

use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialSourceRepository;
use Webauthn\Bundle\Repository\DummyPublicKeyCredentialUserEntityRepository;
use Webauthn\Bundle\Security\Handler\DefaultCreationOptionsHandler;
use Webauthn\Bundle\Security\Handler\DefaultRequestOptionsHandler;
use Webauthn\Bundle\Security\Storage\SessionStorage;
use Webauthn\Bundle\Service\DefaultFailureHandler;
use Webauthn\Bundle\Service\DefaultSuccessHandler;
use Webauthn\Counter\ThrowExceptionIfInvalid;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;
use Webauthn\PublicKeyCredentialCreationOptions;

final class Configuration implements ConfigurationInterface
{
    public function __construct(
        private readonly string $alias
    ) {
    }

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
                if (! isset($v['creation_profiles'])) {
                    $v['creation_profiles'] = null;
                }
                if (! isset($v['request_profiles'])) {
                    $v['request_profiles'] = null;
                }

                return $v;
            })
            ->end()
            ->end();

        $rootNode->children()
            ->scalarNode('http_message_factory')
                ->setDeprecated(
                    'web-auth/webauthn-symfony-bundle',
                    '4.5.0',
                    'The class "http_message_factory" configuration option is deprecated since 4.5.0 and will be removed in 5.0.0. Not needed anymore.'
                )
                ->defaultNull()
                ->info('Creates PSR-7 HTTP Request and Response instances from Symfony ones.')
            ->end()
            ->scalarNode('clock')
                ->defaultValue('webauthn.clock.default')
                ->info('PSR-20 Clock service.')
            ->end()
            ->scalarNode('event_dispatcher')
                ->defaultValue(EventDispatcherInterface::class)
                ->info('PSR-14 Event Dispatcher service.')
            ->end()
            ->scalarNode('request_factory')
            ->defaultNull()
            ->info('PSR-17 Request Factory.')
            ->end()
            ->scalarNode('http_client')
            ->cannotBeEmpty()
            ->defaultValue('webauthn.http_client.default')
            ->info('A Symfony HTTP client.')
            ->end()
            ->scalarNode('logger')
            ->defaultValue('webauthn.logger.default')
            ->info('A PSR-3 logger to receive logs during the processes')
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
            ->defaultNull()
            ->setDeprecated('web-auth/webauthn-symfony-bundle', '4.3.0')
            ->info('This handler will check the token binding header from the request. By default, it is ignored.')
            ->end()
            ->arrayNode('secured_rp_ids')
            ->treatFalseLike(null)
            ->treatTrueLike(null)
            ->treatNullLike(null)
            ->useAttributeAsKey('name')
            ->scalarPrototype()
            ->end()
            ->end()
            ->scalarNode('counter_checker')
            ->defaultValue(ThrowExceptionIfInvalid::class)
            ->cannotBeEmpty()
            ->info(
                'This service will check if the counter is valid. By default it throws an exception (recommended).'
            )
            ->end()
            ->scalarNode('top_origin_validator')
            ->defaultNull()
            ->info('For cross origin (e.g. iframe), this service will be in charge of verifying the top origin.')
            ->end()
            ->end();

        $this->addCreationProfilesConfig($rootNode);
        $this->addRequestProfilesConfig($rootNode);
        $this->addMetadataConfig($rootNode);
        $this->addControllersConfig($rootNode);
        $this->addAndroidSafetynetConfig($rootNode);

        return $treeBuilder;
    }

    private function addCreationProfilesConfig(ArrayNodeDefinition $rootNode): void
    {
        $errorTemplate = 'Invalid value "%s"';
        /** @noRector Rector\DeadCode\Rector\Assign\RemoveUnusedVariableAssignRector */
        $defaultCreationProfiles = [
            'default' => [
                'rp' => [
                    'name' => 'Secured Application',
                ],
            ],
        ];
        $rootNode->children()
            ->arrayNode('creation_profiles')
            ->treatFalseLike($defaultCreationProfiles)
            ->treatNullLike($defaultCreationProfiles)
            ->treatTrueLike($defaultCreationProfiles)
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->addDefaultsIfNotSet()
            ->children()
            ->arrayNode('rp')
            ->isRequired()
            ->children()
            ->scalarNode('id')
            ->defaultNull()
            ->end()
            ->scalarNode('name')
            ->isRequired()
            ->end()
            ->scalarNode('icon')
            ->defaultNull()
            ->end()
            ->end()
            ->end()
            ->integerNode('challenge_length')
            ->min(16)
            ->defaultValue(32)
            ->end()
            ->integerNode('timeout')
            ->min(0)
            ->defaultNull()
            ->end()
            ->arrayNode('authenticator_selection_criteria')
            ->addDefaultsIfNotSet()
            ->beforeNormalization()
            ->ifArray()
            ->then(function (array $v): array {
                if (isset($v['attachment_mode'])) {
                    $v['authenticator_attachment'] = $v['attachment_mode'];
                    unset($v['attachment_mode']);
                }

                return $v;
            })
            ->end()
            ->children()
            ->scalarNode('attachment_mode')
            ->setDeprecated('web-auth/webauthn-symfony-bundle', '4.7.0', 'Use "authenticator_attachment" instead')
            ->defaultValue(AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE)
            ->validate()
            ->ifNotInArray([
                AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
                AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
                AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            ])
            ->thenInvalid($errorTemplate)
            ->end()
            ->end()
            ->scalarNode('authenticator_attachment')
            ->defaultValue(AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE)
            ->validate()
            ->ifNotInArray([
                AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE,
                AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
                AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            ])
            ->thenInvalid($errorTemplate)
            ->end()
            ->end()
            ->booleanNode('require_resident_key')
            ->defaultFalse()
            ->end()
            ->scalarNode('user_verification')
            ->defaultValue(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED)
            ->validate()
            ->ifNotInArray([
                AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
                AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            ])
            ->thenInvalid($errorTemplate)
            ->end()
            ->end()
            ->scalarNode('resident_key')
            ->defaultValue(AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED)
            ->validate()
            ->ifNotInArray([
                AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE,
                AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_DISCOURAGED,
                AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
                AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ])
            ->thenInvalid($errorTemplate)
            ->end()
            ->end()
            ->end()
            ->end()
            ->arrayNode('extensions')
            ->treatFalseLike([])
            ->treatTrueLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->scalarPrototype()
            ->end()
            ->end()
            ->arrayNode('public_key_credential_parameters')
            ->integerPrototype()
            ->end()
            ->requiresAtLeastOneElement()
            ->treatNullLike([])
            ->treatFalseLike([])
            ->treatTrueLike([])
            ->defaultValue([])
            ->end()
            ->scalarNode('attestation_conveyance')
            ->defaultValue(PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE)
            ->end()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    private function addRequestProfilesConfig(ArrayNodeDefinition $rootNode): void
    {
        /** @noRector Rector\DeadCode\Rector\Assign\RemoveUnusedVariableAssignRector */
        $defaultRequestProfiles = [
            'default' => [],
        ];

        $rootNode->children()
            ->arrayNode('request_profiles')
            ->treatFalseLike($defaultRequestProfiles)
            ->treatTrueLike($defaultRequestProfiles)
            ->treatNullLike($defaultRequestProfiles)
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('rp_id')
            ->defaultNull()
            ->end()
            ->integerNode('challenge_length')
            ->min(16)
            ->defaultValue(32)
            ->end()
            ->integerNode('timeout')
            ->min(0)
            ->defaultNull()
            ->end()
            ->scalarNode('user_verification')
            ->defaultValue(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED)
            ->end()
            ->arrayNode('extensions')
            ->treatFalseLike([])
            ->treatTrueLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->scalarPrototype()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    private function addControllersConfig(ArrayNodeDefinition $rootNode): void
    {
        $rootNode->children()
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
            ->scalarNode('options_method')
            ->defaultValue(Request::METHOD_POST)
            ->end()
            ->scalarNode('options_path')
            ->isRequired()
            ->end()
            ->scalarNode('result_method')
            ->defaultValue(Request::METHOD_POST)
            ->end()
            ->scalarNode('result_path')
            ->isRequired()
            ->end()
            ->scalarNode('host')
            ->defaultValue(null)
            ->end()
            ->scalarNode('profile')
            ->defaultValue('default')
            ->end()
            ->scalarNode('options_builder')
            ->info(
                'When set, corresponds to the ID of the Public Key Credential Creation Builder. The profile-based ebuilder is ignored.'
            )
            ->defaultNull()
            ->end()
            ->scalarNode('user_entity_guesser')
            ->isRequired()
            ->end()
            ->scalarNode('options_storage')
            ->defaultValue(SessionStorage::class)
            ->info('Service responsible of the options/user entity storage during the ceremony')
            ->end()
            ->scalarNode('success_handler')
            ->defaultValue(DefaultSuccessHandler::class)
            ->end()
            ->scalarNode('failure_handler')
            ->defaultValue(DefaultFailureHandler::class)
            ->end()
            ->scalarNode('options_handler')
            ->defaultValue(DefaultCreationOptionsHandler::class)
            ->end()
            ->arrayNode('secured_rp_ids')
            ->treatFalseLike([])
            ->treatTrueLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->scalarPrototype()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
            ->arrayNode('request')
            ->treatFalseLike([])
            ->treatNullLike([])
            ->treatTrueLike([])
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('options_method')
            ->defaultValue(Request::METHOD_POST)
            ->end()
            ->scalarNode('options_path')
            ->isRequired()
            ->end()
            ->scalarNode('result_method')
            ->defaultValue(Request::METHOD_POST)
            ->end()
            ->scalarNode('result_path')
            ->isRequired()
            ->end()
            ->scalarNode('host')
            ->defaultValue(null)
            ->end()
            ->scalarNode('profile')
            ->defaultValue('default')
            ->end()
            ->scalarNode('options_builder')
            ->info(
                'When set, corresponds to the ID of the Public Key Credential Creation Builder. The profile-based ebuilder is ignored.'
            )
            ->defaultNull()
            ->end()
            ->scalarNode('options_storage')
            ->defaultValue(SessionStorage::class)
            ->info('Service responsible of the options/user entity storage during the ceremony')
            ->end()
            ->scalarNode('success_handler')
            ->defaultValue(DefaultSuccessHandler::class)
            ->end()
            ->scalarNode('failure_handler')
            ->defaultValue(DefaultFailureHandler::class)
            ->end()
            ->scalarNode('options_handler')
            ->defaultValue(DefaultRequestOptionsHandler::class)
            ->end()
            ->arrayNode('secured_rp_ids')
            ->treatFalseLike([])
            ->treatTrueLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->scalarPrototype()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    private function addMetadataConfig(ArrayNodeDefinition $rootNode): void
    {
        $rootNode->children()
            ->arrayNode('metadata')
            ->canBeEnabled()
            ->info('Enable the support of the Metadata Statements. Please read the documentation for this feature.')
            ->children()
            ->scalarNode('mds_repository')
            ->isRequired()
            ->info('The Metadata Statement repository.')
            ->end()
            ->scalarNode('status_report_repository')
            ->isRequired()
            ->info('The Status Report repository.')
            ->end()
            ->scalarNode('certificate_chain_checker')
            ->cannotBeEmpty()
            ->defaultValue(PhpCertificateChainValidator::class)
            ->info('A Certificate Chain checker.')
            ->end()
            ->end()
            ->end()
            ->end();
    }

    private function addAndroidSafetynetConfig(ArrayNodeDefinition $rootNode): void
    {
        $rootNode->children()
            ->arrayNode('android_safetynet')
                ->addDefaultsIfNotSet()
                ->info('Additional configuration options for the Android SafetyNet attestation.')
                ->children()
                    ->integerNode('leeway')
                        ->defaultValue(0)
                        ->min(0)
                        ->info(
                            'Leeway for timestamp verification in response (in millisecond). At least 2000 msec are recommended.'
                        )
                    ->end()
                    ->integerNode('max_age')
                        ->min(0)
                        ->defaultValue(60000)
                        ->info('Maximum age of the response (in millisecond)')
                    ->end()
                    ->scalarNode('api_key')
                        ->defaultNull()
                        ->info(
                            'If set, the application will verify the statements using Google API. See https://console.cloud.google.com/apis/library to get it.'
                        )
                    ->end()
                    ->scalarNode('http_client')
                        ->defaultValue(HttpClientInterface::class)
                        ->info('Symfony client to use to send the request to Google API.')
                    ->end()
                ->end()
            ->end()
        ->end();
    }
}
