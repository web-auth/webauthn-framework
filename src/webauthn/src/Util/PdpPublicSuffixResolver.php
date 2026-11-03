<?php

declare(strict_types=1);

namespace Webauthn\Util;

use Pdp\Domain;
use Pdp\PublicSuffixList;
use Throwable;

/**
 * {@see PublicSuffixResolver} backed by "jeremykendall/php-domain-parser", an optional dependency.
 *
 * The parser needs a Public Suffix List to work with, and the application decides where that list comes from and how
 * often it is refreshed:
 *
 * ```php
 * $resolver = new PdpPublicSuffixResolver(Rules::fromPath('/path/to/public_suffix_list.dat'));
 * ```
 *
 * This class is only an adapter. Any other domain parser can be used instead by implementing
 * {@see PublicSuffixResolver} directly.
 *
 * @see https://github.com/jeremykendall/php-domain-parser
 */
final readonly class PdpPublicSuffixResolver implements PublicSuffixResolver
{
    public function __construct(
        private PublicSuffixList $publicSuffixList
    ) {
    }

    public static function create(PublicSuffixList $publicSuffixList): self
    {
        return new self($publicSuffixList);
    }

    public function getPublicSuffix(string $host): ?string
    {
        try {
            return $this->publicSuffixList->resolve(Domain::fromIDNA2008($host))
                ->suffix()
                ->value();
        } catch (Throwable) {
            return null;
        }
    }
}
