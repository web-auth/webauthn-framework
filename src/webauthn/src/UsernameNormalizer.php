<?php

declare(strict_types=1);

namespace Webauthn;

/**
 * Gives the canonical form of a username, the one under which the user entity repository resolves it.
 *
 * SimpleFakeCredentialGenerator derives its decoys from this form. When the repository finds an account whatever the
 * spelling of its username (a case-insensitive database collation, a lowercased lookup), two spellings of a registered
 * username return the same credentials. Without the same normalization, two spellings of an unknown username would get
 * two different lists of decoys and give the difference away. The normalization has to reproduce the lookup of the
 * repository exactly: folding the case in front of a case-sensitive repository would reveal the opposite.
 */
interface UsernameNormalizer
{
    public function normalize(string $username): string;
}
