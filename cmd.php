<?php

error_reporting(E_ALL);

$service_port = 8888;
$address = gethostbyname('localhost');

$timeout = 10; //in seconds

/*
====================================================================
1. Server sends client its public key, followed by a newline
-----Encryption starts-----
2. Client sends server its public key, encrypted using the server's public key, followed by a newline
3. Server sends client a newline to confirm is has the key, encrypted using the client's public key
4. Session is started, all communication is encrypted using the recipient's public key and decrypted by the recipient using its private key

RSA type pkcs8 formatted in PEM, public key should be spki in PEM
====================================================================
*/

function substring($string, $from, $to){
    return substr($string, $from, $to - $from);
}

function writeEnc($fp, $send, $serverPub) {
    $tmp = [];
    for($i = 0; $i < ceil(strlen($send)/128); $i++) {
        array_push($tmp, substring($send, $i*128, $i*128+128));
    }
    //print_r($tmp);
    foreach($tmp as $chunk) {
        //echo $chunk;
        openssl_public_encrypt($chunk, $in, $serverPub, OPENSSL_PKCS1_OAEP_PADDING);
        fwrite($fp, $in);
    }
    unset($chunk);
}

function getResponse($encrypted_data, $privateKey) {
    $buff = "";
    for ($i = 0; $i < ceil(strlen($encrypted_data)/512); $i++) {
        $tmp = substr($encrypted_data, $i*512, $i*512+512);

        if(!openssl_private_decrypt($tmp, $decrypted_data, openssl_pkey_get_private($privateKey))) {
            echo "Error\n";
        }

        $buff .= strval($decrypted_data);
    }
    return strlen($buff)."\n";
}

/* Client key pair */
$publicKey;
$privateKey;

if(file_exists('clientkey.pem') && file_exists('clientcert.pem')) {
    echo "Reading client keys from files...";
    $fp = fopen("clientcert.pem", "r");
    $publicKey = fread($fp, 8192);
    fclose($fp);
    $fp=fopen("clientkey.pem", "r");
    $privateKey = fread($fp, 8192);
    fclose($fp);
    echo "OK.\n";
} else {
    echo "Creating new client keys...";
    // Create the private and public key
    $res = openssl_pkey_new(array(
        "digest_alg" => "sha512",
        "private_key_bits" => 4096,
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
    ));
    // Extract the private key from $res to $privKey
    openssl_pkey_export($res, $privKey);
    // Extract the public key from $res to $pubKey
    $pubKey = openssl_pkey_get_details($res);
    $pubKey = $pubKey["key"];

    $keyFile = fopen('clientkey.pem', 'w');
    fwrite($keyFile, $privKey);
    $keyFile = fopen('clientcert.pem', 'w');
    fwrite($keyFile, $pubKey);
    $publicKey = $pubKey;
    $privateKey = $privKey;
    echo "OK.\n";
}

/* Create a TCP/IP socket. */
echo "Attempting to connect to '$address' on port '$service_port'...";
$fp = fsockopen($address, $service_port, $errno, $errstr, $timeout);
echo "OK.\n";
$out = "";
if (!$fp) {
    echo "{ \"error\": \"".$errno."\", \"errorMsg\": \"".$errstr."\" }\n";
} else {
    echo "Reading response:\n\n";
    // while (!feof($fp)) {
    //     $out .= fgets($fp, 800);
    //     //echo $buff;
    // }
    $out = fread($fp, 800);
    // $bytes_left = socket_get_status($fp);
    // if ($bytes_left > 0) {
    //     $result["results"] = fread($fp, $bytes_left["unread_bytes"]);
    // }
    // else {
    //     $result["results"] = "";
    // }
}

$serverPub = $out;

echo $serverPub;

/* Split message into 128 byte chunks to encrypt and send to socket */
writeEnc($fp, $publicKey, $serverPub);
/* Send newline to indicate server that we finished sending */
$out = "\n";
openssl_public_encrypt($out, $in, $serverPub, OPENSSL_PKCS1_OAEP_PADDING);
fwrite($fp, $in);

$out = fread($fp, 512);
//echo $out;
// openssl_private_decrypt($out, $decrypted_data, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
echo getResponse($out, $privateKey);
//echo $decrypted_data;

writeEnc($fp, "{\"cmd\":\"status\"}\n", $serverPub);
echo getResponse($out, $privateKey);


echo "Closing socket...";
fclose($fp);
echo "OK.\n\n";
?>