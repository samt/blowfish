<?php
/*
 * Blowfish
 *
 * Wrapper for php's crypt() function to provide an easy interface for hashing
 * passwords.
 *
 * @author Sam Thompson <sam@emberlabs.org>
 * @license Public Domain
 *
 */

if (CRYPT_BLOWFISH !== 1)
{
	throw new RuntimeException("CRYPT_BLOWFISH not installed or enabled.");
}

if (version_compare(PHP_VERSION, '5.3.0') >= 0)
{
	throw new RuntimeException('This code is not meant to run on PHP versions under 5.3.0');
}

class Blowfish
{
	/*
	 * const crypt()'s blowfish id
	 */
	const BLOWFISH_ID = '$2a$';

	/*
	 * Gen salt
	 * @param string cost - String number 04-31 (WARNING: numbers higher than 12 will cause the algo to run over 1 second usually)
	 * @return string - Salt for crypt()
	 */
	private function genSalt($cost)
	{
		// Make sure cost is proper
		$cost = sprintf("%02d", (int) $cost);

		// Start it off without the blowfish identifier
		$salt = static::BLOWFISH_ID . $cost . '$';

		// Generate a random salt
		for($i = 0; $i < 22; $i++)
		{
			$salt .= substr('./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', mt_rand(0, 63), 1);
		}

		return $salt;
	}

	/*
	 * Hash Password
	 * @param string password - Password to hash
	 * @return string - valid password hash
	 */
	public function hashPassword($password, $cost = '10')
	{
		// Crypt it
		return crypt($password, $this->genSalt($cost));
	}

	/*
	 * Check password
	 * @param string password - Plaintext password to check against
	 * @param string hash - Known hash
	 * @return bool - true if matching, false otherwise
	 */
	public function checkPassword($password, $hash)
	{
		// pull off the type
		list(,$type) = explode('$', $hash);

		if ($type !== '2a')
		{
			throw new RuntimeException('Hash was not a valid Blowfish hash generated from the PHP crypt() function.');
		}

		return ($hash === crypt($password, substr($hash, 0, 29))) ? true : false;
	}
}
