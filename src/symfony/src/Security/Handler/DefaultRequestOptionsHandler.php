<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Handler;

use function is_array;
use RuntimeException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

final readonly class DefaultRequestOptionsHandler implements RequestOptionsHandler
{
    public function __construct(
        private NormalizerInterface $normalizer
    ) {
    }

    public function onRequestOptions(
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        ?PublicKeyCredentialUserEntity $userEntity,
        ?Request $request = null
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
