<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Storage;

use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use function array_key_exists;
use function is_array;
use function sprintf;

final readonly class SessionStorage implements OptionsStorage
{
    private const SESSION_PARAMETER = 'WEBAUTHN_PUBLIC_KEY_OPTIONS';

    public function __construct(
        private RequestStack $requestStack
    ) {
    }

    public function store(Item $item, string|null $tag = null): void
    {
        $session = $this->requestStack->getSession();
        $key = sprintf(
            '%s-%s',
            self::SESSION_PARAMETER,
            hash('xxh128', $item->getPublicKeyCredentialOptions()->challenge)
        );
        $session->set($key, [
            'options' => $item->getPublicKeyCredentialOptions(),
            'userEntity' => $item->getPublicKeyCredentialUserEntity(),
        ]);
    }

    public function get(string $challenge): Item
    {
        $session = $this->requestStack->getSession();
        $key = sprintf('%s-%s', self::SESSION_PARAMETER, hash('xxh128', $challenge));
        $sessionValue = $session->remove($key);
        if (! is_array($sessionValue) || ! array_key_exists('options', $sessionValue) || ! array_key_exists(
            'userEntity',
            $sessionValue
        )) {
            throw new BadRequestHttpException('No public key credential options available for this session.');
        }

        $publicKeyCredentialRequestOptions = $sessionValue['options'];
        $userEntity = $sessionValue['userEntity'];

        if (! $publicKeyCredentialRequestOptions instanceof PublicKeyCredentialOptions) {
            throw new BadRequestHttpException('No public key credential options available for this session.');
        }
        if ($userEntity !== null && ! $userEntity instanceof PublicKeyCredentialUserEntity) {
            throw new BadRequestHttpException('No user entity available for this session.');
        }

        return Item::create($publicKeyCredentialRequestOptions, $userEntity);
    }
}
