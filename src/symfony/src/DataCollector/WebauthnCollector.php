<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\DataCollector;

use Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;

class WebauthnCollector extends DataCollector
{
    public function collect(Request $request, Response $response, ?Exception $exception = null): void
    {
    }

    public function getName()
    {
        return 'webauthn_collector';
    }

    public function reset(): void
    {
        $this->data = [];
    }
}
