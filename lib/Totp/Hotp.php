<?php

/*
	Copyright (c) 2016 Lee Keitel

	Permission is hereby granted, free of charge, to any person obtaining a copy of this
	software and associated documentation files (the "Software"), to deal in the Software
	without restriction, including without limitation the rights to use, copy, modify,
	merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
	permit persons to whom the Software is furnished to do so, subject to the following
	conditions:

	The above copyright notice and this permission notice shall be included in all copies
	or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
	INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
	PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
	FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
	ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

namespace lfkeitel\phptotp;

class Hotp
{
    protected $algo;

    public function __construct($algo = 'sha1')
    {
        $this->algo = $algo;
    }

    public function GenerateToken($key, $count = 0, $length = 6)
    {
        $count = $this->packCounter($count);
        $hash = hash_hmac($this->algo, $count, $key);
        $code = $this->genHTOPValue($hash, $length);

        $code = str_pad($code, $length, "0", STR_PAD_LEFT);
        $code = substr($code, (-1 * $length));

        return $code;
    }

    private function packCounter($counter)
    {
        // the counter value can be more than one byte long,
        // so we need to pack it down properly.
        $cur_counter = array(0, 0, 0, 0, 0, 0, 0, 0);
        for ($i = 7; $i >= 0; $i--) {
            $cur_counter[$i] = pack('C*', $counter);
            $counter = $counter >> 8;
        }

        $bin_counter = implode($cur_counter);

        // Pad to 8 chars
        if (strlen($bin_counter) < 8) {
            $bin_counter = str_repeat(chr(0), 8 - strlen($bin_counter)) . $bin_counter;
        }

        return $bin_counter;
    }

    private function genHTOPValue($hash, $length)
    {
        // store calculate decimal
        $hmac_result = [];

        // Convert to decimal
        foreach (str_split($hash, 2) as $hex) {
            $hmac_result[] = hexdec($hex);
        }

        $offset = (int)$hmac_result[count($hmac_result)-1] & 0xf;

        $code = (int)($hmac_result[$offset] & 0x7f) << 24
            | ($hmac_result[$offset+1] & 0xff) << 16
            | ($hmac_result[$offset+2] & 0xff) << 8
            | ($hmac_result[$offset+3] & 0xff);

        return $code % pow(10, $length);
    }

    public static function GenerateSecret($length = 16)
    {
        if ($length % 8 != 0) {
            throw new \Exception("Length must be a multiple of 8");
        }

        $secret = openssl_random_pseudo_bytes($length, $strong);
        if (!$strong) {
            throw new \Exception("Random string generation was not strong");
        }

        return $secret;
    }
}
