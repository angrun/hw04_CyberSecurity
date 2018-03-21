<?php
require('classes/hashTools.php');

// Simple Ajax form processor
if(isset($_POST['process']) && !empty($_POST['process'])) {

	$string   = (isset($_POST['string'])) ? $_POST['string'] : '';
	$cipher   = (isset($_POST['cipher'])) ? $_POST['cipher'] : '';

	// Get mode, SET it to 0 if input is empty
	$mode     = (int)(isset($_POST['mode'])) ? $_POST['mode'] : 0;
	
	// Get max string length for MD5 bruteforce mode, SET it to 2 if input is empty
	$lenght	  = (isset($_POST['bf_maxlenght'])) ? $_POST['bf_maxlenght'] : 2;
	
	// Get dictionaries for MD5 bruteforce mode, SET atleast one array value if input is empty
	$characters = (isset($_POST['dict'])) ? $_POST['dict'] : array(0);
	
	// Get MD5 decrypt mode, SET it to 0 if input is empty
	$md5_mode   = (int)(isset($_POST['md5_mode'])) ? $_POST['md5_mode'] : 0;
	

	// Process errors
	$errors = [];
	
	// Error strings
	$stringError = 'Please enter string!';
	$cypherError = 'Please enter cipher!';
	$charactersError = 'Please select dictionaries!';
	
	switch($mode) {
		case 0:

			if(!$cipher){
				$errors[] = $cypherError;
			}	
			
			if(!$string){
				$errors[] = $stringError;
			}
			
			if(empty($errors)){
				$result = hashTools::encryptOTP($cipher, $string);
			}
			break;
			
		case 1:
		
			if(!$cipher){
				$errors[] = $cypherError;
			}	
			
			if(!$string){
				$errors[] = $stringError;
			}
			
			if(empty($errors)){
				$result = hashTools::decryptOTP($cipher, $string);
			}
			break;
			
		case 2:
			if(!$string){
				$errors[] = $stringError;
			}
			if(empty($errors)){			
				$result = hashTools::encryptSHA512($string);
			}
			break;
			
		case 3:
		
			if(!$string){
				$errors[] = $stringError;
			}
			
			if($md5_mode == 0){				
				$result = hashTools::decryptMD5DB($string);
			} elseif($md5_mode == 1) {
				$result = hashTools::decryptMD5BF($string, $lenght, $characters);

			}
			break;	
	}	

	$arr = '';
	
	if(!empty($errors)){
		$arr = array('errors' => $errors);
	}elseif(isset($result) && empty($errors)){
		$arr = array('result' => $result);
	}
	echo json_encode($arr);	
	
}
?>