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

namespace Webauthn;

use Assert\Assertion;
use CBOR\Decoder;
use CBOR\StringStream;

class AuthenticatorAssertionResponseValidator
{
    private $credentialRepository;
    private $decoder;

    public function __construct(CredentialRepository $credentialRepository, Decoder $decoder)
    {
        $this->credentialRepository = $credentialRepository;
        $this->decoder = $decoder;
    }

    /**
     * @see https://www.w3.org/TR/webauthn/#registering-a-new-credential
     */
    public function check(string $credentialId, AuthenticatorAssertionResponse $authenticatorAssertionResponse, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, ?string $rpId = null): void
    {
        /* @see 7.2.1 */
        Assertion::true($this->isCredentialIdAllowed($credentialId, $publicKeyCredentialRequestOptions->getAllowCredentials()), 'The credential ID is not allowed.');

        /* @see 7.2.2 */
        Assertion::noContent($authenticatorAssertionResponse->getUserHandle(), 'User Handle not supported.'); //TODO: implementation shall be done.

        /* @see 7.2.3 */
        Assertion::true($this->credentialRepository->has($credentialId), 'No credential public key available for the given credential ID.');

        $attestedCredentialData = $this->credentialRepository->get($credentialId);
        $credentialPublicKey = $attestedCredentialData->getCredentialPublicKey();
        Assertion::notNull($credentialPublicKey, 'No public key available.');

        $credentialPublicKey = $this->decoder->decode(
            new StringStream($credentialPublicKey)
        );

        /** @see 7.2.4 */
        /** @see 7.2.5 */
        //Nothing to do. Use of objets directly

        /** @see 7.2.6 */
        $C = $authenticatorAssertionResponse->getClientDataJSON();

        /* @see 7.2.7 */
        Assertion::eq('webauthn.get', $C->getType(), 'The client data type is not "webauthn.get".');

        /* @see 7.2.8 */
        Assertion::true(hash_equals($publicKeyCredentialRequestOptions->getChallenge(), $C->getChallenge()), 'Invalid challenge.');

        /** @see 7.2.9 */
        $rpId = $rpId ?? $publicKeyCredentialRequestOptions->getRpId();
        Assertion::notNull($rpId, 'No rpId.');

        $parsedRelyingPartyId = parse_url($C->getOrigin());
        Assertion::true(array_key_exists('host', $parsedRelyingPartyId) && \is_string($parsedRelyingPartyId['host']), 'Invalid origin rpId.');

        Assertion::eq($parsedRelyingPartyId['host'], $rpId, 'rpId mismatch.');

        /* @see 7.2.10 */
        Assertion::null($C->getTokenBinding(), 'Token binding not supported.');

        /** @see 7.2.11 */
        $rpIdHash = hash('sha256', $rpId, true);
        Assertion::true(hash_equals($rpIdHash, $authenticatorAssertionResponse->getAuthenticatorData()->getRpIdHash()), 'rpId hash mismatch.');

        /* @see 7.2.12 */
        Assertion::true($authenticatorAssertionResponse->getAuthenticatorData()->isUserPresent(), 'User was not present');

        /* @see 7.2.13 */
        Assertion::false(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED === $publicKeyCredentialRequestOptions->getUserVerification() && !$authenticatorAssertionResponse->getAuthenticatorData()->isUserVerified(), 'User authentication required.');

        /* @see 7.2.14 */
        Assertion::null($authenticatorAssertionResponse->getAuthenticatorData()->getExtensions(), 'Extensions not supported.');

        /** @see 7.2.15 */
        $getClientDataJSONHash = hash('sha256', $authenticatorAssertionResponse->getClientDataJSON()->getRawData(), true);

        /* @see 7.2.16 */
        $coseKey = $credentialPublicKey->getNormalizedData();
        $key = "\04".$coseKey[-2].$coseKey[-3];
        Assertion::eq(1, openssl_verify($authenticatorAssertionResponse->getAuthenticatorData()->getAuthData().$getClientDataJSONHash, $authenticatorAssertionResponse->getSignature(), $this->getPublicKeyAsPem($key), OPENSSL_ALGO_SHA256), 'Invalid signature.');

        /* @see 7.2.17 */
        $storedCounter = $this->credentialRepository->getCounterFor($credentialId);
        $currentCounter = $authenticatorAssertionResponse->getAuthenticatorData()->getSignCount();
        Assertion::greaterThan($currentCounter, $storedCounter, 'Invalid counter.');

        $this->credentialRepository->updateCounterFor($credentialId, $currentCounter);

        /* @see 7.2.18 */
    }

    private function getPublicKeyAsPem(string $key): string
    {
        $der = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42";
        $der .= "\0".$key;

        $pem = '-----BEGIN PUBLIC KEY-----'.PHP_EOL;
        $pem .= chunk_split(base64_encode($der), 64, PHP_EOL);
        $pem .= '-----END PUBLIC KEY-----'.PHP_EOL;

        return $pem;
    }

    private function isCredentialIdAllowed(string $credentialId, array $allowedCredentials): bool
    {
        foreach ($allowedCredentials as $allowedCredential) {
            if (hash_equals($allowedCredential->getId(), $credentialId)) {
                return true;
            }
        }

        return false;
    }
}
