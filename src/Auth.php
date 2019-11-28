<?php
/**
 * MIT License <https://opensource.org/licenses/mit>
 *
 * Copyright (c) 2015 Kerem Güneş
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
declare(strict_types=1);

namespace froq\auth;

use froq\interfaces\Stringable;
use froq\auth\AuthException;

/**
 * Auth.
 * @package froq\auth
 * @object  froq\auth\Auth
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 */
final class Auth implements Stringable
{
    /**
     * Types.
     * @const string
     * @since 4.0
     */
    public const TYPE_BASIC  = 'Basic',
                 TYPE_BEARER = 'Bearer',
                 TYPE_DIGEST = 'Digest',
                 TYPE_OAUTH  = 'OAuth';

    /**
     * Type.
     * @var   string
     * @since 4.0
     */
    private string $type;

    /**
     * Credentials.
     * @var   array<string, string>
     * @since 4.0
     */
    private array $credentials;

    /**
     * Constructor.
     * @param  string|null                $type
     * @param  array<string, string>|null $credentials
     * @since  4.0
     */
    public function __construct(string $type = null, array $credentials = null)
    {
        $type && $this->setType($type);
        $credentials && $this->setCredentials($credentials);
    }

    /**
     * Set type.
     * @param  string $type
     * @return self
     * @since  4.0
     */
    public function setType(string $type): self
    {
        $this->type = $type;

        return $this;
    }

    /**
     * Get type.
     * @return ?string
     * @since  4.0
     */
    public function getType(): ?string
    {
        return $this->type ?? null;
    }

    /**
     * Set credentials.
     * @param  array<string, string> $credentials
     * @return self
     * @since  4.0
     */
    public function setCredentials(array $credentials): self
    {
        $this->credentials = $credentials;

        return $this;
    }

    /**
     * Get credentials.
     * @return ?array
     * @since  4.0
     */
    public function getCredentials(): ?array
    {
        return $this->credentials ?? null;
    }

    /**
     * Validate.
     * @param  ?string $credentials
     * @return bool
     * @throws froq\auth\AuthException
     * @since  4.0
     */
    public function validate(?string $credentials): bool
    {
        $thisType = $this->getType();
        $thisCredentials = $this->getCredentials();

        if ($thisCredentials == null) {
            throw new AuthException('Auth object has no credentials yet, set credentials first '.
                'before validation');
        }

        // Reverse from array if type is basic ($credentials param should be encoded in that case).
        // Example:
        // $auth = new Auth('Basic', ['api_key', 'api_secret']);    // not encoded
        // $auth = new Auth('Basic', ['YXBpX2tleTphcGlfc2VjcmV0']); // encoded
        // var_dump($auth->validate('YXBpX2tleTphcGlfc2VjcmV0'));
        if (self::isBasic($thisType)) {
            $thisCredentials = sscanf($this->toString(), '%[Bb]asic %s');
            $thisCredentials = $thisCredentials[1];
        } else {
            $thisCredentials = $thisCredentials[0];
        }

        return self::validateCredentials($credentials, $thisCredentials);
    }

    /**
     * Validate credentials.
     * @param  ?string $credentials1
     * @param  ?string $credentials2
     * @return bool
     * @since  4.0
     */
    public static function validateCredentials(?string $credentials1, ?string $credentials2): bool
    {
        return $credentials1 && $credentials2 && hash_equals($credentials1, $credentials2);
    }

    /**
     * @inheritDoc froq\interfaces\Stringable
     * @since      4.0
     */
    public function toString(): string
    {
        $type = $this->getType();
        $credentials = $this->getCredentials();

        $ret = ''. $type;

        if ($credentials != null) {
            if (self::isBasic($type) && isset($credentials[0], $credentials[1])) {
                // Eg: 'api_key:api_secret'.
                $ret .= ' '. base64_encode($credentials[0] .':'. $credentials[1]);
            } else {
                // Eg: 'api_key'.
                $ret .= ' '. $credentials[0];
            }
        }

        return $ret;
    }

    /**
     * Parse.
     * @param  string $input
     * @param  bool   $decodeBasicCredentials
     * @return array<string|null, string|null>
     */
    public static function parse(string $input, bool $decodeBasicCredentials = true): array
    {
        // Resources:
        // @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
        // @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization
        // Available types:
        // @link https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
        // @link https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html

        // All accepted:
        // 'YWxhZGRpbjpvcGVuc2VzYW1l'
        // 'Authorization: YWxhZGRpbjpvcGVuc2VzYW1l'
        // 'Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l'
        preg_match('~
            (?:(?:Proxy-)?Authorization\s*:\s*)? # header name
            (?:([\w-]+)\s+)?                     # type (not given everytime)
            (?:(.+)$)                            # credentials
        ~ix', trim($input), $match);

        $type = ($match[1] ?? '') ?: null;
        $credentials = ($match[2] ?? '') ?: null;

        // Basic authorizations only, normally..
        if ($decodeBasicCredentials && $credentials != null && self::isBasic($type)) {
            $credentials = base64_decode($credentials);
        }

        return [$type, $credentials];
    }

    /**
     * Parse auth.
     * @param  string $input
     * @param  bool   $decodeBasicCredentials
     * @return froq\auth\Auth
     * @since  4.0
     */
    public static final function parseAuth(string $input, bool $decodeBasicCredentials = true): Auth
    {
        [$type, $credentials] = self::parse($input, $decodeBasicCredentials);

        return new Auth((string) $type, (array) $credentials);
    }

    /**
     * Is basic.
     * @param  ?string $type
     * @return bool
     * @since  4.0
     * @internal
     */
    private static function isBasic(?string $type): bool
    {
        return strtolower((string) $type) == 'basic';
    }
}

