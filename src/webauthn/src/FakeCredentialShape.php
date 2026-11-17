<?php

declare(strict_types=1);

namespace Webauthn;

use InvalidArgumentException;
use function sprintf;

/**
 * The visible shape of a decoy credential: the length of its credential ID and the transports that the client reported
 * when the credential was registered.
 *
 * A fake credential generator gives each decoy the shape of a credential that real authenticators produce, so that its
 * length and its transports do not tell it apart from a registered credential. The transports are kept unique and in
 * lexicographic order, as the WebAuthn specification requires from getTransports().
 */
final readonly class FakeCredentialShape
{
    /**
     * @var int<16, 1023>
     */
    public int $credentialIdLength;

    /**
     * @var string[]
     */
    public array $transports;

    /**
     * @param string[] $transports
     */
    public function __construct(int $credentialIdLength, array $transports = [])
    {
        ($credentialIdLength >= 16 && $credentialIdLength <= 1023) || throw new InvalidArgumentException(sprintf(
            'The credential ID length must be between 16 and 1023 bytes, got %d.',
            $credentialIdLength
        ));
        $transports = array_values(array_unique($transports));
        sort($transports);

        $this->credentialIdLength = $credentialIdLength;
        $this->transports = $transports;
    }

    /**
     * @param string[] $transports
     */
    public static function create(int $credentialIdLength, array $transports = []): self
    {
        return new self($credentialIdLength, $transports);
    }
}
