<?php

declare(strict_types=1);

namespace Webauthn\Denormalizer;

use CBOR\Decoder;
use CBOR\Normalizable;
use Symfony\Component\Serializer\Exception\BadMethodCallException;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareInterface;
use Symfony\Component\Serializer\Normalizer\DenormalizerAwareTrait;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Webauthn\AttestationStatement\AttestationObject;
use Webauthn\Exception\InvalidDataException;
use Webauthn\StringStream;

final class AttestationObjectDenormalizer implements DenormalizerInterface, DenormalizerAwareInterface
{
    use DenormalizerAwareTrait;

    private const ALREADY_CALLED = 'ATTESTATION_OBJECT_PREPROCESS_ALREADY_CALLED';

    public function denormalize(mixed $data, string $type, string $format = null, array $context = [])
    {
        if ($this->denormalizer === null) {
            throw new BadMethodCallException('Please set a denormalizer before calling denormalize()!');
        }
        $stream = new StringStream($data);
        $parsed = Decoder::create()->decode($stream);

        $parsed instanceof Normalizable || throw InvalidDataException::create(
            $parsed,
            'Invalid attestation object. Unexpected object.'
        );
        $attestationObject = $parsed->normalize();
        $stream->isEOF() || throw InvalidDataException::create(
            null,
            'Invalid attestation object. Presence of extra bytes.'
        );
        $stream->close();

        $data = [
            'rawAttestationObject' => $data,
            'attStmt' => $attestationObject,
            'authData' => $attestationObject['authData'],
        ];
        $context[self::ALREADY_CALLED] = true;

        return $this->denormalizer->denormalize($data, $type, $format, $context);
    }

    public function supportsDenormalization(mixed $data, string $type, string $format = null, array $context = []): bool
    {
        if ($context[self::ALREADY_CALLED] ?? false) {
            return false;
        }

        return $type === AttestationObject::class;
    }

    /**
     * @return array<class-string, bool>
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            AttestationObject::class => false,
        ];
    }
}
