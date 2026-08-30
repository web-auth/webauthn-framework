<?php

declare(strict_types=1);

namespace Webauthn\Bundle\DependencyInjection;

use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\HttpFoundation\Request;
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
use Webauthn\SimpleFakeCredentialGenerator;

final readonly class Configuration implements ConfigurationInterface
{
    public function __construct(
        private string $alias
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
            ->then(static function (array $v): array {
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
            ->scalarNode('fake_credential_generator')
            ->defaultValue(SimpleFakeCredentialGenerator::class)
            ->cannotBeEmpty()
            ->info(
                'A service that implements the FakeCredentialGenerator to generate fake credentials for preventing username enumeration.'
            )
            ->end()
            ->scalarNode('clock')
            ->defaultValue('webauthn.clock.default')
            ->info('PSR-20 Clock service.')
            ->end()
            ->scalarNode('options_storage')
            ->defaultValue(SessionStorage::class)
            ->info('Service responsible of the options/user entity storage during the ceremony')
            ->end()
            ->scalarNode('event_dispatcher')
            ->defaultValue(EventDispatcherInterface::class)
            ->info('PSR-14 Event Dispatcher service.')
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
            ->arrayNode('allowed_origins')
            ->setDeprecated(
                'web-auth/webauthn-symfony-bundle',
                '5.4.0',
                'The "%node%" YAML node is deprecated and will be removed in 6.0. Call "WebauthnAttestationVerifier::withAllowedOrigins(...)" / "WebauthnAssertionVerifier::withAllowedOrigins(...)" on the helper instead. Multi-origin apps can spread a Symfony parameter into the call. Single-origin apps can omit the call entirely: the verifier falls back to the W3C-recommended same-origin check against the request host.'
            )
            ->info(
                'Origins accepted for every ceremony. Security: origins sharing a Relying Party ID rarely share a trust level, and any response produced on any entry of this list is accepted for any ceremony. List only the origins that share the trust level of the endpoint, and prefer several narrow lists (per controller, or per verifier through the helpers) over a single broad one. See webauthn.ceremony_origin_pinning to also require the response to come from the origin the ceremony was started on.'
            )
            ->treatFalseLike([])
            ->treatTrueLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->scalarPrototype()
            ->end()
            ->end()
            ->booleanNode('allow_subdomains')
            ->setDeprecated(
                'web-auth/webauthn-symfony-bundle',
                '5.4.0',
                'The "%node%" YAML node is deprecated and will be removed in 6.0. Call "WebauthnAttestationVerifier::withAllowSubdomains()" / "WebauthnAssertionVerifier::withAllowSubdomains()" on the helper instead.'
            )
            ->info(
                'Accept any subdomain of every allowed origin. Security: MUST stay false whenever a subdomain can be controlled by a third party (customer-provisioned hostnames, user content, staging hosts), since an assertion obtained on such a subdomain would then be accepted on the high-trust origin.'
            )
            ->defaultFalse()
            ->end()
            ->booleanNode('ceremony_origin_pinning')
            ->info(
                'Require the authenticator response to be produced on the very origin the ceremony was started on, on top of the allow list. Defaults to the value passed to WebauthnAttestationVerifier::withCeremonyOriginPinning() / WebauthnAssertionVerifier::withCeremonyOriginPinning(). Fails closed: ceremonies stored without an origin are rejected, so keep it disabled for native app facets (android:apk-key-hash:...) and for flows whose options request and ceremony do not share an origin. See https://github.com/w3c/webauthn/issues/2466'
            )
            ->defaultFalse()
            ->end()
            ->arrayNode('related_origins')
            ->addDefaultsIfNotSet()
            ->info('Related Origin Requests (WebAuthn Level 3) settings, applied to the "/.well-known/webauthn" endpoint.')
            ->children()
            ->scalarNode('public_suffix_resolver')
            ->defaultNull()
            ->info(
                'Service implementing Webauthn\\Util\\PublicSuffixResolver, used to derive the eTLD+1 label of the published origins. Without it the label limit cannot be checked. "Webauthn\\Util\\PdpPublicSuffixResolver" adapts "jeremykendall/php-domain-parser".'
            )
            ->end()
            ->booleanNode('label_limit_check')
            ->defaultTrue()
            ->info(
                'Warns when the published origins resolve to more than 5 distinct eTLD+1 labels: clients silently ignore the extra ones. Set to false to opt out of the check.'
            )
            ->end()
            ->end()
            ->end()
            ->arrayNode('secured_rp_ids')
            ->setDeprecated(
                'web-auth/webauthn-symfony-bundle',
                '5.2.0',
                'The "secured_rp_ids" node is deprecated. Please use "allowed_origins" and "allow_subdomains" instead.'
            )
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
        $this->addClientOverridePolicyConfig($rootNode);
        $this->addMetadataConfig($rootNode);
        $this->addControllersConfig($rootNode);
        $this->addPasskeyEndpointsConfig($rootNode);

        return $treeBuilder;
    }

    private function addClientOverridePolicyConfig(ArrayNodeDefinition $rootNode): void
    {
        $rootNode->children()
            ->arrayNode('client_override_policy')
            ->setDeprecated(
                'web-auth/webauthn-symfony-bundle',
                '5.4.0',
                'The "%node%" YAML section is deprecated and will be removed in 6.0. Build a "Webauthn\\Bundle\\Policy\\ClientOverridePolicy" inline in your controller and attach it to the helper via "WebauthnCreationOptionsBuilder::withClientOverrides()" / "WebauthnRequestOptionsBuilder::withClientOverrides()".'
            )
            ->addDefaultsIfNotSet()
            ->info('Configuration for allowing client request values to override profile configuration')
            ->children()
            ->arrayNode('user_verification')
            ->addDefaultsIfNotSet()
            ->children()
            ->booleanNode('enabled')
            ->defaultFalse()
            ->info('Whether to allow client requests to override the user verification requirement')
            ->end()
            ->arrayNode('allowed_values')
            ->defaultValue(['required', 'preferred'])
            ->scalarPrototype()
            ->end()
            ->info('List of allowed values for user verification requirement')
            ->end()
            ->end()
            ->end()
            ->arrayNode('authenticator_attachment')
            ->addDefaultsIfNotSet()
            ->children()
            ->booleanNode('enabled')
            ->defaultTrue()
            ->info('Whether to allow client requests to override the authenticator attachment')
            ->end()
            ->arrayNode('allowed_values')
            ->defaultValue(['platform', 'cross-platform'])
            ->scalarPrototype()
            ->end()
            ->info('List of allowed values for authenticator attachment')
            ->end()
            ->end()
            ->end()
            ->arrayNode('resident_key')
            ->addDefaultsIfNotSet()
            ->children()
            ->booleanNode('enabled')
            ->defaultTrue()
            ->info('Whether to allow client requests to override the resident key requirement')
            ->end()
            ->arrayNode('allowed_values')
            ->defaultValue(['required', 'preferred', 'discouraged'])
            ->scalarPrototype()
            ->end()
            ->info('List of allowed values for resident key requirement')
            ->end()
            ->end()
            ->end()
            ->arrayNode('attestation_conveyance')
            ->addDefaultsIfNotSet()
            ->children()
            ->booleanNode('enabled')
            ->defaultTrue()
            ->info('Whether to allow client requests to override the attestation conveyance preference')
            ->end()
            ->arrayNode('allowed_values')
            ->defaultValue(['none', 'indirect', 'direct', 'enterprise'])
            ->scalarPrototype()
            ->end()
            ->info('List of allowed values for attestation conveyance')
            ->end()
            ->end()
            ->end()
            ->arrayNode('extensions')
            ->addDefaultsIfNotSet()
            ->children()
            ->booleanNode('enabled')
            ->defaultTrue()
            ->info('Whether to allow client requests to override extensions')
            ->end()
            ->end()
            ->end()
            ->arrayNode('mediation')
            ->addDefaultsIfNotSet()
            ->children()
            ->booleanNode('enabled')
            ->defaultFalse()
            ->info('Whether to allow client requests to request the conditional mediation flow (auto-register).')
            ->end()
            ->arrayNode('allowed_values')
            ->defaultValue([
                PublicKeyCredentialCreationOptions::MEDIATION_DEFAULT,
                PublicKeyCredentialCreationOptions::MEDIATION_CONDITIONAL,
            ])
            ->scalarPrototype()
            ->end()
            ->info('List of allowed mediation values')
            ->end()
            ->end()
            ->end()
            ->end()
            ->end()
            ->end();
    }

    private function addCreationProfilesConfig(ArrayNodeDefinition $rootNode): void
    {
        $errorTemplate = 'Invalid value "%s"';
        /** @noRector Rector\DeadCode\Rector\Assign\RemoveUnusedVariableAssignRector */
        $defaultCreationProfiles = [
            'default' => [
                'rp' => [
                    'name' => '',
                ],
            ],
        ];
        $rootNode->children()
            ->arrayNode('creation_profiles')
            ->setDeprecated(
                'web-auth/webauthn-symfony-bundle',
                '5.4.0',
                'The "%node%" YAML section is deprecated and will be removed in 6.0. Use the autowired "Webauthn\\Bundle\\Service\\WebauthnOptionsResponse::forCreation()" helper from a controller of your own; see the "Options Helpers" documentation.'
            )
            ->treatFalseLike($defaultCreationProfiles)
            ->treatNullLike($defaultCreationProfiles)
            ->treatTrueLike($defaultCreationProfiles)
            ->useAttributeAsKey('name')
            ->arrayPrototype()
            ->addDefaultsIfNotSet()
            ->children()
            ->arrayNode('rp')
            ->children()
            ->scalarNode('id')
            ->defaultNull()
            ->end()
            ->scalarNode('name')
            ->setDeprecated(
                'web-auth/webauthn-symfony-bundle',
                '5.3.0',
                'The child node "%node%" at path "%path%" is deprecated and will be removed in the next major release.'
            )
            ->defaultValue('')
            ->end()
            ->scalarNode('icon')
            ->setDeprecated(
                'web-auth/webauthn-symfony-bundle',
                '5.1.0',
                'The child node "%node%" at path "%path%" is deprecated and has no effect.'
            )
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
            ->booleanNode('conditional_create')
            ->defaultFalse()
            ->info(
                'Enable Conditional Create (auto-register) for this profile. When true, user presence can be false after password authentication. See https://github.com/w3c/webauthn/wiki/Explainer:-Conditional-Create'
            )
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
            ->setDeprecated(
                'web-auth/webauthn-symfony-bundle',
                '5.4.0',
                'The "%node%" YAML section is deprecated and will be removed in 6.0. Use the autowired "Webauthn\\Bundle\\Service\\WebauthnOptionsResponse::forRequest()" helper from a controller of your own; see the "Options Helpers" documentation.'
            )
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
            ->setDeprecated(
                'web-auth/webauthn-symfony-bundle',
                '5.4.0',
                'The "%node%" YAML section is deprecated and will be removed in 6.0. Write your own controllers using the autowired "Webauthn\\Bundle\\Service\\WebauthnOptionsResponse" and "Webauthn\\Bundle\\Service\\WebauthnResponseVerifier" helpers; see the "Options Helpers" and "Verification Helpers" documentation.'
            )
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
            ->defaultNull()
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
            ->scalarNode('hide_existing_credentials')
            ->info(
                'In order to prevent username enumeration, the existing credentials can be hidden. This is highly recommended when the attestation ceremony is performed by anonymous users.'
            )
            ->defaultFalse()
            ->end()
            ->scalarNode('options_storage')
            ->setDeprecated(
                'web-auth/webauthn-symfony-bundle',
                '5.2.0',
                'The child node "%node%" at path "%path%" is deprecated. Please use the root option "options_storage" instead.'
            )
            ->defaultNull()
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
            ->arrayNode('allowed_origins')
            ->info(
                'Origins accepted by this controller only. Overrides the global "webauthn.allowed_origins" list. Security: list only the origins that share the trust level of this endpoint, so that a response produced on a lower-trust origin of the global list cannot be replayed here.'
            )
            ->treatFalseLike([])
            ->treatTrueLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->scalarPrototype()
            ->end()
            ->end()
            ->booleanNode('allow_subdomains')
            ->info(
                'Accept any subdomain of this controller allowed origins. Security: MUST stay false whenever a subdomain can be controlled by a third party.'
            )
            ->defaultFalse()
            ->end()
            ->arrayNode('secured_rp_ids')
            ->setDeprecated(
                'web-auth/webauthn-symfony-bundle',
                '5.2.0',
                'The "secured_rp_ids" node is deprecated. Please use "allowed_origins" and "allow_subdomains" instead.'
            )
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
            ->defaultNull()
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
            ->setDeprecated(
                'web-auth/webauthn-symfony-bundle',
                '5.2.0',
                'The child node "%node%" at path "%path%" is deprecated. Please use the root option "options_storage" instead.'
            )
            ->defaultNull()
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
            ->arrayNode('allowed_origins')
            ->info(
                'Origins accepted by this controller only. Overrides the global "webauthn.allowed_origins" list. Security: list only the origins that share the trust level of this endpoint, so that a response produced on a lower-trust origin of the global list cannot be replayed here.'
            )
            ->treatFalseLike([])
            ->treatTrueLike([])
            ->treatNullLike([])
            ->useAttributeAsKey('name')
            ->scalarPrototype()
            ->end()
            ->end()
            ->booleanNode('allow_subdomains')
            ->info(
                'Accept any subdomain of this controller allowed origins. Security: MUST stay false whenever a subdomain can be controlled by a third party.'
            )
            ->defaultFalse()
            ->end()
            ->arrayNode('secured_rp_ids')
            ->setDeprecated(
                'web-auth/webauthn-symfony-bundle',
                '5.2.0',
                'The "secured_rp_ids" node is deprecated. Please use "allowed_origins" and "allow_subdomains" instead.'
            )
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

    private function addPasskeyEndpointsConfig(ArrayNodeDefinition $rootNode): void
    {
        $rootNode->children()
            ->arrayNode('passkey_endpoints')
            ->canBeEnabled()
            ->info(
                'Enable the .well-known/passkey-endpoints discovery endpoint as defined in the W3C Passkey Endpoints specification.'
            )
            ->children()
            ->append($this->getUrlNode('enroll', 'URL to the passkey enrollment/creation interface.'))
            ->append($this->getUrlNode('manage', 'URL to the passkey management interface.'))
            ->append(
                $this->getUrlNode(
                    'prf_usage_details',
                    'URL to informational page about PRF (Pseudo-Random Function) extension usage.'
                )
            )
            ->end()
            ->end()
            ->end();
    }

    private function getUrlNode(string $name, string $info): ArrayNodeDefinition
    {
        $treeBuilder = new TreeBuilder($name);
        $node = $treeBuilder->getRootNode();
        $node
            ->info($info)
            ->beforeNormalization()
            ->ifString()
            ->then(static fn (string $v): array => [
                'path' => $v,
            ])
            ->end()
            ->children()
            ->scalarNode('path')
            ->isRequired()
            ->info('The absolute HTTPS URL or Symfony route name.')
            ->example(['https://example.com/enroll', 'app_passkey_enroll'])
            ->end()
            ->arrayNode('params')
            ->treatFalseLike([])
            ->treatTrueLike([])
            ->treatNullLike([])
            ->prototype('variable')
            ->end()
            ->info('Route parameters (only used when path is a Symfony route name).')
            ->end()
            ->end()
            ->end();

        return $node;
    }
}
