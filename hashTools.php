<?php
// Parsing library

require('simple_html_dom.php');  //Library, parser, require - is essential
  
class hashTools

{

    // The encryptOTP function uses modular arithmetics to encrypt a user's message.  It requires the cipher keys and the
    // plain text message as input parameters.
    public static function encryptOTP($cipherKey, $plainText)
    {
		if(!$cipherKey OR !$plainText){
			return false;
		}		
		$plainText = preg_replace('/[^A-Z]/', '', strtoupper($plainText)); // User's input from A-Z and converting it to Upper cases
		$cipherKey = preg_replace('/[^A-Z]/', '', strtoupper($cipherKey)); // User's input (key) from A-Z and converting it to Upper case

        if (strlen($cipherKey) < strlen($plainText)) { // Condition if the key is shorter than the input - return nothing
            return false;
        }

        $cipherText = ''; //
        for ($letter = 0; $letter < strlen($plainText); $letter++) {
            $plainTextCharacterAscii   = ord($plainText[$letter]);
            $cipherKeyCharacterAscii   = ord($cipherKey[$letter]);
            $plainTextCharacterInteger = $plainTextCharacterAscii - 65;
            $cipherKeyCharacterInteger = $cipherKeyCharacterAscii - 65;
            $oneTimePad                = ($plainTextCharacterInteger + $cipherKeyCharacterInteger) % 26;
            $cipherTextCharacterAscii  = $oneTimePad + 65;
            $cipherText .= chr($cipherTextCharacterAscii);
        }
        return ($cipherText);
    }

    public static function decryptOTP($cipherKey, $cipherText)
    {
		if(!$cipherKey OR !$cipherText){
			return false;
		}
		
		$cipherText = preg_replace('/[^A-Z]/', '', strtoupper($cipherText));
		$cipherKey = preg_replace('/[^A-Z]/', '', strtoupper($cipherKey));	
        if (strlen($cipherKey) < strlen($cipherText)) {
            return false;
        }
        $plainText = '';
        for ($letter = 0; $letter < strlen($cipherText); $letter++) {
            $cipherTextCharacterAscii   = ord($cipherText[$letter]);
            $cipherKeyCharacterAscii    = ord($cipherKey[$letter]);
            $cipherTextCharacterInteger = $cipherTextCharacterAscii - 65;
            $cipherKeyCharacterInteger  = $cipherKeyCharacterAscii - 65;
            $oneTimePad                 = ($cipherTextCharacterInteger - $cipherKeyCharacterInteger + 26) % 26;
            $plainTextCharacterAscii    = $oneTimePad + 65;
            $plainText .= chr($plainTextCharacterAscii);
        }
        return ($plainText);
    }


    // Generate SHA with in-built php method "hash"
	public static function encryptSHA512($string)
	{
		if(!$string){
			return false;
		}
		return hash('sha512', $string);
	}


	// This method uses url (https://md5.gromweb.com/) as data base source (though this was not really allowed),
    // but this method makes any (almost) hash decrypted !
    public static function decryptMD5DB($string)
    {
		if(!$string){
			return false;
		}		
		// Create URL
        $url     = 'https://md5.gromweb.com/?md5=' . $string . '';
		
        // Add http headers to imitate a real user (not a bot)
        $opts    = array(
            'http' => array(
                'header' => "User-Agent:Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X; en-us) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53\r\n"
            )
        );
        $context = stream_context_create($opts);
		
        // Parse web page with simple html dom lib
        $html    = file_get_html('https://md5.gromweb.com/?md5=' . $string, 0, $context);

        // Retrieve tag with result
        if(isset($html->find('div#content em.string', 0)->plaintext)) {
			return $html->find('div#content em.string', 0)->plaintext;
		} else {
			return 'No matches';
		}
    }

    // Bruteforce method to decrypt MD5, generate all possible combination with chosen dictionary and match them with input MD5 string.
    public static function decryptMD5BF($string, $maxLength = 2, $characters = array(0))
    {
		if(!$string){
			return false;
		}
		
	    // Create dictionary
		$dictionary = '';
		foreach($characters as $character){
			if($character == 0){
				$dictionary .= 'abcdefghijklmnopqrstuvwxyz';
			}
	
			if($character == 1){
				$dictionary .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';				
			} 
			
			if($character == 2){
				$dictionary .= '0123456789';				
			} 			
			
			if($character == 3){
				$dictionary .= '~`!@#$%^&*()-_\/\'";:,.+=<>? ';
			} 				
		}

		$size = strlen($dictionary);
		$base = array();
		$counter = 0;
		$baseSize = 1;
		// How many combinations exist for the given length and charset
		$combinations = 0;
		for($i=1;$i<=$maxLength;$i++) {
			$combinations += pow($size,$i);
		} 

		while($baseSize <= $maxLength) {
			// Go through all the possible combinations of last character and output $base
			for($i=0;$i<$size;$i++) {
				$base[0] = $i;
				
				$val = '';
				for($j=$baseSize-1;$j>=0;$j--) {
					$val .= $dictionary[$base[$j]];
				}

				if($string == md5($val)){
					return $val;
				}
				unset($val);

			}
			// How many $base elements reached their max?
			for($i=0;$i<$baseSize;$i++) {
				if($base[$i] == $size-1)
				    $counter++;
				else break;
			}
			// Expand array and set values to 0.
			if($counter == $baseSize) {

				for($i=0;$i<=$baseSize;$i++) {
					$base[$i] = 0;
				}
				$baseSize = count($base);
			}

			else {
				$base[$counter]++;
				for($i=0;$i<$counter;$i++) $base[$i] = 0;
			}
			$counter=0;
		}
		return 'No matches';
	}
	
}