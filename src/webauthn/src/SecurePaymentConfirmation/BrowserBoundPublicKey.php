<?php

declare(strict_types=1);

namespace Webauthn\SecurePaymentConfirmation;

use CBOR\Decoder;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use Cose\Key\Key;
use const FILTER_VALIDATE_INT;
use function filter_var;
use Throwable;
use Webauthn\Exception\InvalidDataException;
use Webauthn\StringStream;

/**
 * W3C Secure Payment Confirmation: the browser-bound public key.
 *
 * The client data carries it in `payment.browserBoundPublicKey`, at registration and at authentication, as the
 * base64url encoding of a COSE_Key, encoded like the credential public key of the attested credential data. This
 * object holds the decoded COSE_Key bytes. The serializer reads and writes the base64url string.
 *
 * The bytes are only decoded when {@see self::algorithm()} or {@see self::coseKey()} is called, with the CBOR and COSE
 * libraries, the same way for both. {@see BrowserBoundSignatureVerifier} goes through them as well.
 *
 * @see https://w3c.github.io/secure-payment-confirmation/#sctn-collectedclientadditionalpaymentdata-dictionary
 * @see https://w3c.github.io/secure-payment-confirmation/#sctn-collectedclientadditionalpaymentregistrationdata-dictionary
 */
class BrowserBoundPublicKey
{
    /**
     * @param string $publicKey COSE_Key bytes
     */
    public function __construct(
        public readonly string $publicKey,
    ) {
        $publicKey !== '' || throw InvalidDataException::create(
            $publicKey,
            'The browser-bound public key must not be empty.'
        );
    }

    public static function create(string $publicKey): self
    {
        return new self($publicKey);
    }

    /**
     * The COSE algorithm identifier of the key, its `alg` member (label 3), for instance -7 for ES256. The user agent
     * picks it among the `browserBoundPubKeyCredParams` of the payment extension input, or among the `pubKeyCredParams`
     * of the creation options when that list is empty.
     *
     * @throws InvalidDataException when the bytes are not a CBOR map, or when the key has no `alg` member encoded as a
     *                              CBOR integer
     */
    public function algorithm(): int
    {
        return $this->algorithmOf($this->decode());
    }

    /**
     * The decoded COSE_Key, as the browser-bound signature is verified with it.
     *
     * @throws InvalidDataException when the bytes are not a COSE_Key with an `alg` member encoded as a CBOR integer
     */
    public function coseKey(): Key
    {
        $map = $this->decode();
        $this->algorithmOf($map);
        try {
            /** @var array<int|string, mixed> $data */
            $data = $map->normalize();

            return Key::createFromData($data);
        } catch (Throwable $e) {
            throw InvalidDataException::create(
                $this->publicKey,
                'Invalid browserBoundPublicKey: the COSE_Key is invalid.',
                $e
            );
        }
    }

    /**
     * @throws InvalidDataException
     */
    private function decode(): MapObject
    {
        $stream = new StringStream($this->publicKey);
        try {
            $object = Decoder::create()->decode($stream);
        } catch (Throwable $e) {
            throw InvalidDataException::create(
                $this->publicKey,
                'Invalid browserBoundPublicKey: the COSE_Key cannot be decoded.',
                $e
            );
        }
        $stream->isEOF() || throw InvalidDataException::create(
            $this->publicKey,
            'Invalid browserBoundPublicKey: extra bytes after the COSE key.'
        );
        $stream->close();
        $object instanceof MapObject || throw InvalidDataException::create(
            $this->publicKey,
            'Invalid browserBoundPublicKey: expected a CBOR map.'
        );

        return $object;
    }

    /**
     * The `alg` member is read from the CBOR map itself, before the normalization that renders the CBOR integers and
     * the CBOR text strings alike as PHP strings, so that a text string such as "-7" is refused. Only an integer
     * label 3 designates it, and its value must be a CBOR integer that fits in a PHP integer.
     *
     * @throws InvalidDataException
     */
    private function algorithmOf(MapObject $map): int
    {
        foreach ($map as $item) {
            $label = $item->getKey();
            if (! $label instanceof UnsignedIntegerObject || $label->getValue() !== (string) Key::ALG) {
                continue;
            }
            $value = $item->getValue();
            $algorithm = $value instanceof UnsignedIntegerObject || $value instanceof NegativeIntegerObject
                ? filter_var($value->getValue(), FILTER_VALIDATE_INT)
                : false;
            $algorithm !== false || throw $this->noIntegerAlgorithm();

            return $algorithm;
        }

        throw $this->noIntegerAlgorithm();
    }

    private function noIntegerAlgorithm(): InvalidDataException
    {
        return InvalidDataException::create(
            $this->publicKey,
            'Invalid browserBoundPublicKey: the COSE_Key has no integer "alg" member.'
        );
    }
}
