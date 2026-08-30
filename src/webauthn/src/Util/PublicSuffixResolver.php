<?php

declare(strict_types=1);

namespace Webauthn\Util;

/**
 * Resolves the public suffix (eTLD) of a host, so that the registrable domain (eTLD+1) and the label preceding the
 * suffix can be derived. The Related Origin Requests limit is expressed in terms of that label, hence the contract.
 *
 * The library deliberately ships no public suffix data: the Public Suffix List changes weekly, and freezing a copy of
 * it inside a WebAuthn library would turn a compliance hint into a maintenance burden. Implement this interface on top
 * of the domain parser of your choice; {@see PdpPublicSuffixResolver} is provided for
 * "jeremykendall/php-domain-parser".
 *
 * @see https://publicsuffix.org/
 */
interface PublicSuffixResolver
{
    /**
     * Returns the public suffix of the given host, or null when the host has none: IP literals, single-label hosts
     * such as "localhost", and hosts that are a public suffix themselves (e.g. "co.uk").
     */
    public function getPublicSuffix(string $host): ?string;
}
