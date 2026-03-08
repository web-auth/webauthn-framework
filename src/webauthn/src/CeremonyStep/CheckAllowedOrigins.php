<?php

declare(strict_types=1);

namespace Webauthn\CeremonyStep;

use function count;
use function in_array;
use InvalidArgumentException;
use function is_array;
use function is_string;
use function sprintf;
use function trigger_deprecation;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

final readonly class CheckAllowedOrigins implements CeremonyStep
{
    /**
     * @var string[]
     */
    private array $allowedOrigins;

    /**
     * @param string[] $allowedOrigins
     */
    public function __construct(
        array $allowedOrigins,
        private bool $allowSubdomains = false
    ) {
        foreach ($allowedOrigins as $allowedOrigin) {
            $parsedAllowedOrigin = parse_url($allowedOrigin);
            $parsedAllowedOrigin !== false || throw new InvalidArgumentException(sprintf(
                'Invalid origin: %s',
                $allowedOrigin
            ));
        }

        $this->allowedOrigins = array_unique($allowedOrigins);
    }

    public function process(
        CredentialRecord $credentialRecord,
        AuthenticatorAssertionResponse|AuthenticatorAttestationResponse $authenticatorResponse,
        PublicKeyCredentialRequestOptions|PublicKeyCredentialCreationOptions $publicKeyCredentialOptions,
        ?string $userHandle,
        string $host
    ): void {
        if ($credentialRecord instanceof PublicKeyCredentialSource) {
            trigger_deprecation(
                'web-auth/webauthn-lib',
                '5.3',
                'Passing a PublicKeyCredentialSource to "%s::process()" is deprecated, pass a CredentialRecord instead.',
                self::class
            );
        }
        $authData = $authenticatorResponse instanceof AuthenticatorAssertionResponse ? $authenticatorResponse->authenticatorData : $authenticatorResponse->attestationObject->authData;
        $C = $authenticatorResponse->clientDataJSON;

        $parsedRelyingPartyId = parse_url($C->origin);
        $clientDataRpId = $parsedRelyingPartyId['host'] ?? '';
        if ($clientDataRpId === '') {
            $clientDataRpId = $C->origin;
        }
        is_array($parsedRelyingPartyId) || throw AuthenticatorResponseVerificationException::create(
            'Invalid origin. Unable to parse the origin.'
        );
        if (in_array($C->origin, $this->allowedOrigins, true)) {
            return;
        }
        $allowedHosts = array_map(
            static fn (string $origin): string => parse_url($origin, PHP_URL_HOST) ?? $origin,
            $this->allowedOrigins
        );
        $isSubDomain = $this->isSubdomain($allowedHosts, $clientDataRpId);
        if ($this->allowSubdomains && $isSubDomain) {
            return;
        }
        if (! $this->allowSubdomains && $isSubDomain) {
            throw AuthenticatorResponseVerificationException::create('Invalid origin. Subdomains are not allowed.');
        }
        if (count($this->allowedOrigins) !== 0) {
            throw AuthenticatorResponseVerificationException::create(
                'Invalid origin. Not in the list of allowed origins.'
            );
        }

        $rpId = $publicKeyCredentialOptions->rpId ?? $publicKeyCredentialOptions->rp->id ?? $host;
        $facetId = $this->getFacetId($rpId, $publicKeyCredentialOptions->extensions, $authData->extensions);
        $facetId !== '' || throw AuthenticatorResponseVerificationException::create(
            'Invalid origin. Unable to determine the facet ID.'
        );
        if ($clientDataRpId === $facetId) {
            return;
        }
        $isSubDomains = $this->isSubdomainOf($clientDataRpId, $facetId);
        if ($this->allowSubdomains && $isSubDomains) {
            return;
        }
        if (! $this->allowSubdomains && $isSubDomains) {
            throw AuthenticatorResponseVerificationException::create('Invalid origin. Subdomains are not allowed.');
        }

        $scheme = $parsedRelyingPartyId['scheme'] ?? '';
        $scheme === 'https' || throw AuthenticatorResponseVerificationException::create(
            'Invalid scheme. HTTPS required.'
        );
    }

    private function isSubdomainOf(string $subdomain, string $domain): bool
    {
        return str_ends_with('.' . $subdomain, '.' . $domain);
    }

    private function getFacetId(
        string $rpId,
        AuthenticationExtensions $AuthenticationExtensions,
        ?AuthenticationExtensions $authenticationExtensionsClientOutputs
    ): string {
        if ($authenticationExtensionsClientOutputs === null
            || ! $AuthenticationExtensions->has('appid')
            || ! $authenticationExtensionsClientOutputs->has('appid')) {
            return $rpId;
        }

        $appId = $AuthenticationExtensions->get('appid')
            ->value;
        $wasUsed = $authenticationExtensionsClientOutputs->get('appid')
            ->value;

        return (is_string($appId) && $wasUsed === true) ? $appId : $rpId;
    }

    /**
     * @param string[] $origins
     */
    private function isSubdomain(array $origins, string $domain): bool
    {
        foreach ($origins as $allowedOrigin) {
            if ($this->isSubdomainOf($domain, $allowedOrigin)) {
                return true;
            }
        }
        return false;
    }
}
