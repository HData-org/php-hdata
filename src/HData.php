<?php

class HData {

    /*
    How it connects:
    ====================================================================
    1. Server sends client its public key, followed by a newline
    -----Encryption starts-----
    2. Client sends server its public key, encrypted using the server's public key, followed by a newline
    3. Server sends client a newline to confirm is has the key, encrypted using the client's public key
    4. Session is started, all communication is encrypted using the recipient's public key and decrypted by the recipient using its private key
    ====================================================================
    */

    private $host;
    private $address;
	private $port;
	private $timeout;

    private $debug;

	private $socket;
    private $serverPub;
    private $keypair;

    /* Public methods */

    public function __construct($host = '127.0.0.1', $port = 8888, $timeout = 10, $debug = false)
    {
        $this->host = $host;
        $this->port = $port;
        $this->timeout = $timeout;
        $this->debug = $debug;
        $this->serverPub;
        $this->keypair = [];

        $this->debug ? error_reporting(E_ALL) : "";

        $this->connect();
    }

    public function __destruct()
	{
		$this->closeSocket();
	}

    public function connect() {

        //validate host
		if (filter_var($this->host, FILTER_VALIDATE_IP)) {
			//host is ip => address is host
			$this->address = $this->host;
		} else {
			//find domain ip
			$resolvedIp = gethostbyname($this->host);
			if (filter_var($resolvedIp, FILTER_VALIDATE_IP)) {
				//resolvedIp is a valid IP => address is resolvedIp
				$this->address = $resolvedIp;
			}
        }

        $this->createKeyPair();
        $this->openSocket();
        $this->handshake();
    }

    public function sendCmd($cmd) {
        $this->writeEnc($cmd."\n");
        return $this->getResponse(fread($this->socket, 1024));
    }

    /* Commands */

    public function getStatus() {
        return $this->sendCmd("{ \"cmd\": \"status\" }");
    }

    public function login($user, $password) {
        return $this->sendCmd("{ \"cmd\": \"login\", \"user\": \"".$user."\", \"password\": \"".$password."\" }");
    }

    public function logout() {
        return $this->sendCmd("{ \"cmd\": \"logout\" }");
    }

    /* Private methods */

    private function substring($string, $from, $to) {
        return substr($string, $from, $to - $from);
    }
    
    private function endsWith($haystack, $needle) {
        $length = strlen($needle);
        return $length > 0 ? substr($haystack, -$length) === $needle : true;
    }

    private function writeEnc($send) {
        $tmp = [];
        for($i = 0; $i < ceil(strlen($send)/128); $i++) {
            array_push($tmp, $this->substring($send, $i*128, $i*128+128));
        }
        foreach($tmp as $chunk) {
            openssl_public_encrypt($chunk, $in, $this->serverPub, OPENSSL_PKCS1_OAEP_PADDING);
            fwrite($this->socket, $in);
        }
        unset($chunk);
    }

    private function getResponse($encrypted_data) {
        $buff = "";
        $encrypted_data_length = strlen($encrypted_data);
        for ($i = 0; $i < ceil($encrypted_data_length/512); $i++) {

            $tmp = substr($encrypted_data, $i*512, $i*512+512);
            if(!openssl_private_decrypt($tmp, $decrypted_data, $this->keypair['privateKey'], OPENSSL_PKCS1_OAEP_PADDING)) {
                echo "{\"error\":\"Private Decryption Error\"}\n";
            }
            $buff .= $decrypted_data;
            if($this->endsWith($buff, "\n")) {
                return $buff;
                $buff = "";
            }

        }
    }

    private function createKeyPair() {
        if(file_exists('.htprivkey.pem') && file_exists('clientcert.pem')) {
            echo $this->debug ? "Reading client keys from files..." : "";

            // Read client keys from files
            $fp=fopen(".htprivkey.pem", "r");
            $this->keypair['privateKey'] = fread($fp, 8192);
            fclose($fp);
            $fp = fopen("clientcert.pem", "r");
            $this->keypair['publicKey'] = fread($fp, 8192);
            fclose($fp);

            echo $this->debug ? "OK.\n" : "";
        } else {
            echo $this->debug ? "Creating new client keys..." : "";

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
            // Write keys to files
            $keyFile = fopen('.htprivkey.pem', 'w');
            fwrite($keyFile, $privKey);
            fclose($keyFile);
            $keyFile = fopen('clientcert.pem', 'w');
            fwrite($keyFile, $pubKey);
            fclose($keyFile);
            $this->keypair['publicKey'] = $pubKey;
            $this->keypair['privateKey'] = $privKey;
            
            echo $this->debug ? "OK.\n" : "";
        }
    }

    private function handshake() {
        echo $this->debug ? "Reading response:\n\n" : "";

        $response = fread($this->socket, 1024);

        $this->serverPub = $response;

        echo $this->debug ? $this->serverPub : "";

        // Split message into 128 byte chunks to encrypt and send to socket
        $this->writeEnc($this->keypair['publicKey']);

        // Recive encrypted newline from server
        $response = fread($this->socket, 1024);

        // Decrypte message from server
        $decrypted = $this->getResponse($response);

        echo $this->debug ? $decrypted : "";

        return $decrypted;
    }

    private function openSocket() {
        echo $this->debug ? "Attempting to connect to '$this->host' on port '$this->port'..." : "";

        $this->socket = fsockopen($this->address, $this->port, $errno, $errstr, $this->timeout);

        echo $this->debug ? "OK.\n" : "";

        if (!$this->socket) {
            echo "{\"error\":\"".$errno."\",\"errorMsg\":\"".$errstr."\"}\n";
            return false;
        }
    }

    private function closeSocket() {
		if ($this->socket !== null) {
            echo $this->debug ? "Closing socket..." : "";

            fclose($this->socket);
			$this->socket = null;
            
            echo $this->debug ? "OK.\n\n" : "";
		}
	}

}

?>