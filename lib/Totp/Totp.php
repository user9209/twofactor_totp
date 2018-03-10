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

class Totp extends Hotp
{
    private $startTime;
    private $timeInterval;

    public function __construct($algo = 'sha1', $start = 0, $ti = 30)
    {
        parent::__construct($algo);
        $this->startTime = $start;
        $this->timeInterval = $ti;
    }

    public function GenerateToken($key, $time = null, $length = 6)
    {
        // Pad the key if necessary
        if ($this->algo === 'sha256') {
            $key = $key . substr($key, 0, 12);
        } elseif ($this->algo === 'sha512') {
            $key = $key . $key . $key . substr($key, 0, 4);
        }

        // Get the current unix timestamp if one isn't given
        if (is_null($time)) {
            $time = (new \DateTime())->getTimestamp();
        }

        // Calculate the count
        $now = $time - $this->startTime;
        $count = floor($now / $this->timeInterval);

        // Generate a normal HOTP token
        return parent::GenerateToken($key, $count, $length);
    }
}
