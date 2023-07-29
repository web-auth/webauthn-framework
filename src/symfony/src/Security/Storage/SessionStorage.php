<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Storage;

use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use function array_key_exists;
use function is_array;

final class SessionStorage implements OptionsStorage
{
    private const SESSION_PARAMETER = 'WEBAUTHN_PUBLIC_KEY_OPTIONS';

    public function __construct(
        private readonly RequestStack $requestStack
    ) {
    }

    public function store(Item $item, string|null $tag = null): void
    {
        $session = $this->requestStack->getSession();
        $session->set(self::SESSION_PARAMETER, [
            'options' => $item->getPublicKeyCredentialOptions(),
            'userEntity' => $item->getPublicKeyCredentialUserEntity(),
        ]);
    }

    public function get(string|null $tag = null): Item
    {
        $session = $this->requestStack->getSession();
        $sessionValue = $session->remove(self::SESSION_PARAMETER);
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
