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

/**
 * Auth.
 * @package froq\auth
 * @object  froq\auth\Auth
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   3.0
 */
final /* static */ class Auth
{
    /**
     * Get authorization type.
     * @param  string $input
     * @return ?string
     */
    public static function getAuthorizationType(string $input): ?string
    {
        return self::parseAuthorization($input, false)[0];
    }

    /**
     * Get authorization credentials.
     * @param  string $input
     * @param  bool   $decode
     * @return ?string
     */
    public static function getAuthorizationCredentials(string $input, bool $decode = false): ?string
    {
        return self::parseAuthorization($input, $decode)[1];
    }

    /**
     * Parse authorization.
     * @param  string $input
     * @param  bool   $decodeBasicCredentials
     * @return array
     */
    public static function parseAuthorization(string $input, bool $decodeBasicCredentials = true): array
    {
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization

        // all accepted
        // $input = 'YWxhZGRpbjpvcGVuc2VzYW1l';
        // $input = 'Authorization: YWxhZGRpbjpvcGVuc2VzYW1l';
        // $input = 'Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l';
        preg_match('~
            (?:(?:Proxy-)?Authorization\s*:\s*)? # header name
            (?:([\w-]+)\s+)?                     # type (not given everytime)
            (?:([^\s]+))                         # credentials
        ~ix', trim($input), $matches);

        $type =@ $matches[1] ?: null;
        $credentials =@ $matches[2] ?: null;

        // basic authorizations only, normally..
        if ($decodeBasicCredentials && $type != null && $credentials != null
            && strtolower($type) == 'basic') {
            $credentials = base64_decode($credentials);
        }

        return [$type, $credentials];
    }
}
