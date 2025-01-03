<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Routing;

use Symfony\Component\Config\Loader\Loader as SymfonyLoader;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use function sprintf;

class Loader extends SymfonyLoader
{
    private readonly RouteCollection $routes;

    public function __construct()
    {
        parent::__construct();
        $this->routes = new RouteCollection();
    }

    public function add(string $pattern, ?string $host, string $name, string $method = 'POST'): void
    {
        $controllerId = sprintf('%s', $name);
        $defaults = [
            '_controller' => $controllerId,
        ];
        $route = new Route($pattern, $defaults, [], [], $host, [], [$method]);
        $this->routes->add($name, $route);
    }

    /**
     * @noRector
     */
    public function load(mixed $resource, ?string $type = null): RouteCollection
    {
        return $this->routes;
    }

    public function supports(mixed $resource, ?string $type = null): bool
    {
        return $type === 'webauthn';
    }
}
