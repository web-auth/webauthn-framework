<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use const JSON_THROW_ON_ERROR;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

trait SerializerTrait
{
    protected function serialize(mixed $data): string
    {
        $serializer = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();

        return $serializer->serialize($data, JsonEncoder::FORMAT, [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
        ]);
    }

    /**
     * @template T of object
     * @param class-string<T> $class
     * @return T
     */
    protected function deserialize(string $data, string $class): mixed
    {
        $serializer = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();

        /** @var T */
        return $serializer->deserialize($data, $class, JsonEncoder::FORMAT);
    }
}
