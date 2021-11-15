<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Storage;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

interface OptionsStorage
{
    public function store(Request $request, StoredData $data, Response $response): void;

    public function get(Request $request): StoredData;
}
