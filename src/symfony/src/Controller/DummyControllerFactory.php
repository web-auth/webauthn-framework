<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Controller;

use JetBrains\PhpStorm\Pure;

final class DummyControllerFactory
{
    #[Pure]
    public function create(): DummyController
    {
        return new DummyController();
    }
}
