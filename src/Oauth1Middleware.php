<?php declare(strict_types=1);

namespace ApiClients\Middleware\Oauth1;

use ApiClients\Foundation\Middleware\DefaultPriorityTrait;
use ApiClients\Foundation\Middleware\ErrorTrait;
use ApiClients\Foundation\Middleware\MiddlewareInterface;
use ApiClients\Foundation\Middleware\PostTrait;
use ApiClients\Tools\Psr7\Oauth1\Definition;
use ApiClients\Tools\Psr7\Oauth1\RequestSigning\RequestSigner;
use Psr\Http\Message\RequestInterface;
use React\EventLoop\LoopInterface;
use React\Promise\CancellablePromiseInterface;
use function GuzzleHttp\Psr7\parse_query;
use function React\Promise\resolve;
use function WyriHaximus\React\futurePromise;

class Oauth1Middleware implements MiddlewareInterface
{
    use DefaultPriorityTrait;
    use PostTrait;
    use ErrorTrait;

    /**
     * @var LoopInterface
     */
    private $loop;

    /**
     * @param LoopInterface $loop
     */
    public function __construct(LoopInterface $loop)
    {
        $this->loop = $loop;
    }

    /**
     * @param RequestInterface $request
     * @param array $options
     * @return CancellablePromiseInterface
     */
    public function pre(RequestInterface $request, array $options = []): CancellablePromiseInterface
    {
        if (!$this->validateOptions($options)) {
            return resolve($request);
        }

        return futurePromise($this->loop, [$request, $options])->then(function ($args) {
            return resolve($this->signRequest(...$args));
        });
    }

    private function validateOptions(array $options): bool
    {
        if (!isset($options[self::class])) {
            return false;
        }

        foreach ([
            Options::CONSUMER_KEY,
            Options::CONSUMER_SECRET,
            Options::ACCESS_TOKEN,
            Options::TOKEN_SECRET,
        ] as $option) {
            if (!isset($options[self::class][$option])) {
                return false;
            }

            if (!($options[self::class][$option] instanceof $option)) {
                return false;
            }
        }

        return true;
    }

    private function signRequest(RequestInterface $request, array $options): RequestInterface
    {
        return (new RequestSigner(
            new Definition\ConsumerKey($options[self::class][Options::CONSUMER_KEY]),
            new Definition\ConsumerSecret($options[self::class][Options::CONSUMER_SECRET])
        ))->withAccessToken(
            new Definition\AccessToken($options[self::class][Options::ACCESS_TOKEN]),
            new Definition\TokenSecret($options[self::class][Options::TOKEN_SECRET])
        )->sign($request);
    }
}
