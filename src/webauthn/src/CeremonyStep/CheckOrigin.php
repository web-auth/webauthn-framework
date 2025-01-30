<?php

declare(strict_types=1);

namespace Webauthn\CeremonyStep;

use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use function in_array;
use function is_array;
use function is_string;
use function strlen;

final readonly class CheckOrigin implements CeremonyStep
{
    /**
     * @param string[] $securedRelyingPartyId
     */
    public function __construct(
        private array $securedRelyingPartyId
    ) {
    }

    public function process(
        PublicKeyCredentialSource $publicKeyCredentialSource,
        AuthenticatorAssertionResponse|AuthenticatorAttestationResponse $authenticatorResponse,
        PublicKeyCredentialRequestOptions|PublicKeyCredentialCreationOptions $publicKeyCredentialOptions,
        ?string $userHandle,
        string $host
    ): void {
        $authData = $authenticatorResponse instanceof AuthenticatorAssertionResponse ? $authenticatorResponse->authenticatorData : $authenticatorResponse->attestationObject->authData;
        $C = $authenticatorResponse->clientDataJSON;
        $rpId = $publicKeyCredentialOptions->rpId ?? $publicKeyCredentialOptions->rp->id ?? $host;
        $facetId = $this->getFacetId($rpId, $publicKeyCredentialOptions->extensions, $authData->extensions);
        $parsedRelyingPartyId = parse_url($C->origin);
        is_array($parsedRelyingPartyId) || throw AuthenticatorResponseVerificationException::create(
            'Invalid origin'
        );
        // Companion application
        if (in_array($parsedRelyingPartyId['scheme'], ['android', 'ios'])) {
            in_array($C->origin, $this->securedRelyingPartyId, true) || throw AuthenticatorResponseVerificationException::create(
                'Unauthorized origin.'
            );
            return;
        }
        // Web
        if (! in_array($facetId, $this->securedRelyingPartyId, true)) {
            $scheme = $parsedRelyingPartyId['scheme'] ?? '';
            $scheme === 'https' || throw AuthenticatorResponseVerificationException::create(
                'Invalid scheme. HTTPS required.'
            );
        }
        $clientDataRpId = $parsedRelyingPartyId['host'] ?? '';
        $clientDataRpId !== '' || throw AuthenticatorResponseVerificationException::create('Invalid origin rpId.');
        $rpIdLength = strlen($facetId);

        substr(
            '.' . $clientDataRpId,
            -($rpIdLength + 1)
        ) === '.' . $facetId || throw AuthenticatorResponseVerificationException::create('rpId mismatch.');
    }

    private function getFacetId(
        string $rpId,
        AuthenticationExtensions $AuthenticationExtensions,
        null|AuthenticationExtensions $authenticationExtensionsClientOutputs
    ): string {
        if ($authenticationExtensionsClientOutputs === null || ! $AuthenticationExtensions->has(
            'appid'
        ) || ! $authenticationExtensionsClientOutputs->has('appid')) {
            return $rpId;
        }
        $appId = $AuthenticationExtensions->get('appid')
            ->value;
        $wasUsed = $authenticationExtensionsClientOutputs->get('appid')
            ->value;
        if (! is_string($appId) || $wasUsed !== true) {
            return $rpId;
        }
        return $appId;
    }
}
