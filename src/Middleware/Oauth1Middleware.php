<?php declare(strict_types=1);

namespace ApiClients\Foundation\Oauth1\Middleware;

use ApiClients\Foundation\Middleware\MiddlewareInterface;
use ApiClients\Foundation\Middleware\PostTrait;
use ApiClients\Foundation\Oauth1\Options;
use JacobKiers\OAuth\Consumer\ConsumerInterface;
use JacobKiers\OAuth\Request\Request as OAuthRequest;
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

        if (!($options[self::class][Options::SIGNATURE_METHOD] instanceof SignatureMethodInterface)) {
            return false;
        }

        return true;
    }

    private function signRequest(RequestInterface $request, array $options): RequestInterface
    {
        $oauthRequest = OAuthRequest::fromConsumerAndToken(
            $options[self::class][Options::CONSUMER],
            $options[self::class][Options::TOKEN],
            $request->getMethod(),
            (string)$request->getUri(),
            $this->extractParamsFromQuery(
                $request->getUri()->getQuery()
            )
        );
        $oauthRequest->setParameter('oauth_version', '1.0', false);
        $oauthRequest->signRequest(
            $options[self::class][Options::SIGNATURE_METHOD],
            $options[self::class][Options::CONSUMER],
            $options[self::class][Options::TOKEN]
        );

        return $request->withAddedHeader(
            'Authorization',
            trim(substr($oauthRequest->toHeader(), 15))
        );
    }

    private function extractParamsFromQuery(string $query): array
    {
        $params = parse_query($query);

        uksort($params, 'strcmp');

        foreach ($params as $key => $value) {
            if ($value !== null) {
                continue;
            }

            unset($params[$key]);
        }

        return $params;
    }
}
