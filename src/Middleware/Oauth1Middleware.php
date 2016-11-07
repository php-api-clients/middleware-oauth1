<?php declare(strict_types=1);

namespace ApiClients\Foundation\Oauth1\Middleware;

use ApiClients\Foundation\Middleware\MiddlewareInterface;
use ApiClients\Foundation\Middleware\PostTrait;
use ApiClients\Foundation\Oauth1\Options;
use ApiClients\Tools\Psr7\Oauth1\Definition;
use ApiClients\Tools\Psr7\Oauth1\RequestSigning\RequestSigner;
use JacobKiers\OAuth\Consumer\ConsumerInterface;
use JacobKiers\OAuth\SignatureMethod\SignatureMethodInterface;
use JacobKiers\OAuth\Token\TokenInterface;
use Psr\Http\Message\RequestInterface;
use React\EventLoop\LoopInterface;
use React\Promise\CancellablePromiseInterface;
use function React\Promise\resolve;
use function GuzzleHttp\Psr7\parse_query;
use function WyriHaximus\React\futurePromise;

class Oauth1Middleware implements MiddlewareInterface
{
    use PostTrait;

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

        if (!isset($options[self::class][Options::CONSUMER])) {
            return false;
        }

        if (!($options[self::class][Options::CONSUMER] instanceof ConsumerInterface)) {
            return false;
        }

        if (!isset($options[self::class][Options::TOKEN])) {
            return false;
        }

        if (!($options[self::class][Options::TOKEN] instanceof TokenInterface)) {
            return false;
        }

        if (!isset($options[self::class][Options::SIGNATURE_METHOD])) {
            return false;
        }

        return true;
    }

    private function signRequest(RequestInterface $request, array $options): RequestInterface
    {
        /** @var ConsumerInterface */
        $consumer = $options[self::class][Options::CONSUMER];

        /** @var TokenInterface */
        $token = $options[self::class][Options::TOKEN];

        return (new RequestSigner(
            new Definition\ConsumerKey($consumer->getKey()),
            new Definition\ConsumerSecret($consumer->getSecret())
        ))->withAccessToken(
            new Definition\AccessToken($token->getKey()),
            new Definition\TokenSecret($token->getSecret())
        )->sign($request);
    }
}
