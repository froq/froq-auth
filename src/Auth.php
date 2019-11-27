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

use froq\auth\AuthException;
use froq\interfaces\Stringable;

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
     * @var   array<string,string|null>
     * @since 4.0
     */
    private array $credentials;

    /**
     * Constructor.
     * @param  string $type
     * @param  array  $credentials
     * @throws froq\auth\AuthException If credentials is empty.
     * @since  4.0
     */
    public function __construct(string $type, array $credentials)
    {
        if ($credentials == null) {
            throw new AuthException('Empty credentials not allowed');
        }

        $this->type = $type;
        $this->credentials = $credentials;
    }

    /**
     * Type.
     * @return string
     * @since  4.0
     */
    public function type(): string
    {
        return $this->type;
    }

    /**
     * Credentials.
     * @return array
     * @since  4.0
     */
    public function credentials(): array
    {
        return $this->credentials;
    }

    /**
     * @inheritDoc froq\interfaces\Stringable
     * @since      4.0
     */
    public function toString(): string
    {
        $ret = $this->type;

        if (ucfirst(strtolower($this->type)) == self::TYPE_BASIC) {
            $credentials = $this->credentials[0];
            if (isset($this->credentials[1])) {
                $credentials .= ':'. $this->credentials[1];
            }
            $ret .= ' '. base64_encode($credentials);
        } else {
            $ret .= ' '. $this->credentials[0];
        }

        return $ret;
    }

    /**
     * Parse.
     * @param  string $input
     * @param  bool   $decodeBasicCredentials
     * @return array<string,string|null>
     */
    public static function parse(string $input, bool $decodeBasicCredentials = true): array
    {
        // Resources;
        // @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
        // @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization
        // available types;
        // @link https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
        // @link https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html

        // All accepted;
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
        if ($decodeBasicCredentials && $credentials != null && $type != null &&
            ucfirst(strtolower($type)) == self::TYPE_BASIC) {
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

        if ($credentials != null && strchr($credentials, ':') != false) {
            $credentials = explode(':', $credentials, 2);
        }

        return new Auth((string) $type, (array) $credentials);
    }
}
