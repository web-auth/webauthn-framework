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
use Psr\Http\Message\ServerRequestInterface;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\TokenBinding\TokenBindingHandler;

class AuthenticatorAssertionResponseValidator
{
    /**
     * @var CredentialRepository
     */
    private $credentialRepository;

    /**
     * @var Decoder
     */
    private $decoder;

    /**
     * @var TokenBindingHandler
     */
    private $tokenBindingHandler;

    /**
     * @var ExtensionOutputCheckerHandler
     */
    private $extensionOutputCheckerHandler;

    public function __construct(CredentialRepository $credentialRepository, Decoder $decoder, TokenBindingHandler $tokenBindingHandler, ExtensionOutputCheckerHandler $extensionOutputCheckerHandler)
    {
        $this->credentialRepository = $credentialRepository;
        $this->decoder = $decoder;
        $this->tokenBindingHandler = $tokenBindingHandler;
        $this->extensionOutputCheckerHandler = $extensionOutputCheckerHandler;
    }

    /**
     * @see https://www.w3.org/TR/webauthn/#verifying-assertion
     */
    public function check(string $credentialId, AuthenticatorAssertionResponse $authenticatorAssertionResponse, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, ServerRequestInterface $request, ?string $userHandle): void
    {
        /* @see 7.2.1 */
        if (0 !== \count($publicKeyCredentialRequestOptions->getAllowCredentials())) {
            Assertion::true($this->isCredentialIdAllowed($credentialId, $publicKeyCredentialRequestOptions->getAllowCredentials()), 'The credential ID is not allowed.');
        }

        /* @see 7.2.2 */
        Assertion::true($this->has($credentialId), 'The credential ID is invalid.');

        /* @see 7.2.3 */
        $attestedCredentialData = $this->get($credentialId);
        $credentialUserHandle = $this->getUserHandleFor($credentialId);
        $responseUserHandle = $authenticatorAssertionResponse->getUserHandle();

        /* @see 7.2.2 User Handle*/
        if (null !== $userHandle) { //If the user was identified before the authentication ceremony was initiated,
            Assertion::eq($credentialUserHandle, $userHandle, 'Invalid user handle');
            if (null !== $responseUserHandle && '' !== $responseUserHandle) {
                Assertion::eq($credentialUserHandle, $responseUserHandle, 'Invalid user handle');
            }
        } else {
            Assertion::notEmpty($responseUserHandle, 'User handle is mandatory');
            Assertion::eq($credentialUserHandle, $responseUserHandle, 'Invalid user handle');
        }

        $credentialPublicKey = $attestedCredentialData->getCredentialPublicKey();
        Assertion::notNull($credentialPublicKey, 'No public key available.');

        $credentialPublicKeyStream = $this->decoder->decode(
            new StringStream($credentialPublicKey)
        );

        /** @see 7.2.4 */
        /** @see 7.2.5 */
        //Nothing to do. Use of objects directly

        /** @see 7.2.6 */
        $C = $authenticatorAssertionResponse->getClientDataJSON();

        /* @see 7.2.7 */
        Assertion::eq('webauthn.get', $C->getType(), 'The client data type is not "webauthn.get".');

        /* @see 7.2.8 */
        Assertion::true(hash_equals($publicKeyCredentialRequestOptions->getChallenge(), $C->getChallenge()), 'Invalid challenge.');

        /** @see 7.2.9 */
        $rpId = $publicKeyCredentialRequestOptions->getRpId() ?? $request->getUri()->getHost();
        $rpIdLength = mb_strlen($rpId);
        $parsedRelyingPartyId = \Safe\parse_url($C->getOrigin());
        Assertion::keyExists($parsedRelyingPartyId, 'scheme', 'Invalid origin rpId.');
        Assertion::eq('https', $parsedRelyingPartyId['scheme'], 'Invalid scheme. HTTPS required.');
        Assertion::keyExists($parsedRelyingPartyId, 'host', 'Invalid origin rpId.');
        $clientDataRpId = $parsedRelyingPartyId['host'];
        Assertion::notEmpty($clientDataRpId, 'Invalid origin rpId.');
        Assertion::eq(mb_substr($clientDataRpId, -$rpIdLength), $rpId, 'rpId mismatch.');

        /* @see 7.2.10 */
        if (null !== $C->getTokenBinding()) {
            $this->tokenBindingHandler->check($C->getTokenBinding(), $request);
        }

        /** @see 7.2.11 */
        $facetId = $this->getFacetId($rpId, $publicKeyCredentialRequestOptions->getExtensions(), $authenticatorAssertionResponse->getAuthenticatorData()->getExtensions());
        $rpIdHash = hash('sha256', $rpId, true);
        Assertion::true(hash_equals($rpIdHash, $authenticatorAssertionResponse->getAuthenticatorData()->getRpIdHash()), 'rpId hash mismatch.');

        /* @see 7.2.12 */
        Assertion::true($authenticatorAssertionResponse->getAuthenticatorData()->isUserPresent(), 'User was not present');

        /* @see 7.2.13 */
        Assertion::false(AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED === $publicKeyCredentialRequestOptions->getUserVerification() && !$authenticatorAssertionResponse->getAuthenticatorData()->isUserVerified(), 'User authentication required.');

        /* @see 7.2.14 */
        $extensions = $authenticatorAssertionResponse->getAuthenticatorData()->getExtensions();
        if (null !== $extensions) {
            $this->extensionOutputCheckerHandler->check($extensions);
        }

        /** @see 7.2.15 */
        $getClientDataJSONHash = hash('sha256', $authenticatorAssertionResponse->getClientDataJSON()->getRawData(), true);

        /* @see 7.2.16 */
        $coseKey = $credentialPublicKeyStream->getNormalizedData();
        $key = "\04".$coseKey[-2].$coseKey[-3];
        Assertion::eq(1, openssl_verify($authenticatorAssertionResponse->getAuthenticatorData()->getAuthData().$getClientDataJSONHash, $authenticatorAssertionResponse->getSignature(), $this->getPublicKeyAsPem($key), OPENSSL_ALGO_SHA256), 'Invalid signature.');

        /* @see 7.2.17 */
        $storedCounter = $this->getCounterFor($credentialId);
        $currentCounter = $authenticatorAssertionResponse->getAuthenticatorData()->getSignCount();
        Assertion::greaterThan($currentCounter, $storedCounter, 'Invalid counter.');

        $this->updateCounterFor($credentialId, $currentCounter);

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

    private function has(string $credentialId): bool
    {
        if ($this->credentialRepository instanceof PublicKeyCredentialSourceRepository) {
            return null !== $this->credentialRepository->findOneByCredentialId($credentialId);
        }

        return $this->credentialRepository->has($credentialId);
    }

    private function get(string $credentialId): AttestedCredentialData
    {
        if ($this->credentialRepository instanceof PublicKeyCredentialSourceRepository) {
            $credentialSource = $this->credentialRepository->findOneByCredentialId($credentialId);
            Assertion::notNull($credentialSource);

            return $credentialSource->getAttestedCredentialData();
        }

        return $this->credentialRepository->get($credentialId);
    }

    private function getUserHandleFor(string $credentialId): string
    {
        if ($this->credentialRepository instanceof PublicKeyCredentialSourceRepository) {
            $credentialSource = $this->credentialRepository->findOneByCredentialId($credentialId);
            Assertion::notNull($credentialSource);

            return $credentialSource->getUserHandle();
        }

        return $this->credentialRepository->getUserHandleFor($credentialId);
    }

    private function getCounterFor(string $credentialId): int
    {
        if ($this->credentialRepository instanceof PublicKeyCredentialSourceRepository) {
            $credentialSource = $this->credentialRepository->findOneByCredentialId($credentialId);
            Assertion::notNull($credentialSource);

            return $credentialSource->getCounter();
        }

        return $this->credentialRepository->getCounterFor($credentialId);
    }

    public function updateCounterFor(string $credentialId, int $newCounter): void
    {
        if ($this->credentialRepository instanceof PublicKeyCredentialSourceRepository) {
            $credentialSource = $this->credentialRepository->findOneByCredentialId($credentialId);
            Assertion::notNull($credentialSource);
            $credentialSource->setCounter($newCounter);
            $this->credentialRepository->saveCredentialSource($credentialSource);

            return;
        }

        $this->credentialRepository->updateCounterFor($credentialId, $newCounter);
    }

    private function getFacetId(string $rpId, AuthenticationExtensionsClientInputs $authenticationExtensionsClientInputs, ?AuthenticationExtensionsClientOutputs $authenticationExtensionsClientOutputs): string
    {
        switch (true) {
            case !$authenticationExtensionsClientInputs->has('appid'):
                return $rpId;
            case null === $authenticationExtensionsClientOutputs:
                return $rpId;
            case !$authenticationExtensionsClientOutputs->has('appid'):
                return $rpId;
            case true !== $authenticationExtensionsClientOutputs->get('appid'):
                return $rpId;
            default:
                return $authenticationExtensionsClientInputs->get('appid');
        }
    }
}
