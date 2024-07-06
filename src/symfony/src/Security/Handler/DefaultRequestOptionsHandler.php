<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Handler;

use RuntimeException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use function is_array;

final class DefaultRequestOptionsHandler implements RequestOptionsHandler
{
    public function __construct(
        private readonly NormalizerInterface $normalizer
    ) {
    }

    public function onRequestOptions(
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        ?PublicKeyCredentialUserEntity $userEntity
    ): Response {
        $data = $this->normalizer->normalize($publicKeyCredentialRequestOptions, JsonEncoder::FORMAT, [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]);
        is_array($data) || throw new RuntimeException('Unable to encode the response to JSON.');
        $data['status'] = 'ok';
        $data['errorMessage'] = '';

        return new JsonResponse($data);
    }
}
