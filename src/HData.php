<?php

namespace HData\HData;

class HData {

    /*
    The HData handshake:
    ====================================================================
    1. Client opens TCP/IP socket
    2. Server sends client its public key, followed by a newline
    -----Encryption starts-----
    3. Client sends server its public key, encrypted using the server's public key, followed by a newline
    4. Server sends client a newline to confirm is has the key, encrypted using the client's public key
    5. Session is started, all communication is encrypted using the recipient's public key and decrypted by the recipient using its private key
    ====================================================================
    */
    
    private $host;
    private $address;
    private $port;
    private $timeout;

    private $debug;

    private $socket;
    private $keypair;
    private $serverPub;

    /* Public methods */

    public function __construct($host = '127.0.0.1', $port = 8888, $debug = false, $timeout = 10)
    {
        $this->host = $host;
        $this->port = $port;
        $this->timeout = $timeout;
        $this->debug = $debug;
        $this->keypair = [];
        $this->serverPub;

        $this->debug ? error_reporting(E_ALL) : "";

        $this->connect();
    }

    public function __destruct()
	{
		$this->disconnect();
	}

    public function connect() {
        //validate host
		if (filter_var($this->host, FILTER_VALIDATE_IP)) {
			$this->address = $this->host;
		} else {
			$resolvedIp = gethostbyname($this->host);
			if (filter_var($resolvedIp, FILTER_VALIDATE_IP)) {
				$this->address = $resolvedIp;
			} else {
                echo $this->debug ? $this->host." is not a valid host" : "";

                $this->address = $this->host;
            }
        }

        $this->getKeyPair();
        $this->openSocket();
        $this->handshake();
    }

    public function close() {
        if(!$this->socket == null) {
            $this->logout();
        }
        $this->closeSocket();
    }

    public function disconnect() {
        $this->closeSocket();
    }

    public function sendCmd($cmd) {
        $cmd = json_encode($cmd);
        $this->writeEnc($cmd."\n");
        return $this->getResponse(fread($this->socket, 1024));
    }

    /* Commands */

    public function getStatus() {
        $cmd = [ "cmd" => "status" ];
        return $this->sendCmd($cmd);
    }
    public function login($user, $password) {
        $cmd = [ "cmd" => "login", "user" => $user, "password" => $password ];
        return $this->sendCmd($cmd);
    }
    public function logout() {
        $cmd = [ "cmd" => "logout" ];
        return $this->sendCmd($cmd);
    }
    public function createUser($user, $password, $permissions) {
        $cmd = [ "cmd" => "createuser", "user" => $user, "password" => $password, "permissions" => $permissions ];
        return $this->sendCmd($cmd);
    }
    public function deleteUser($user) {
        $cmd = [ "cmd" => "deleteuser", "user" => $user ];
        return $this->sendCmd($cmd);
    }
    public function getUser($user) {
        $cmd = [ "cmd" => "getuser", "user" => $user ];
        return $this->sendCmd($cmd);
    }
    public function updateUser($user, $property, $content) {
        $cmd = [ "cmd" => "updateuser", "user" => $user, "property" => $property, "content" => $content ];
        return $this->sendCmd($cmd);
    }
    public function updatePassword($user, $password) {
        $cmd = [ "cmd" => "updatepassword", "user" => $user, "password" => $password ];
        return $this->sendCmd($cmd);
    }
    public function createTable($tableName) {
        $cmd = [ "cmd" => "createtable", "table" => $tableName ];
        return $this->sendCmd($cmd);
    }
    public function deleteTable($tableName) {
        $cmd = [ "cmd" => "deletetable", "table", $tableName ];
        return $this->sendCmd($cmd);
    }
    public function getKey($tableName, $keyName) {
        $cmd = [ "cmd" => "getkey", "table" => $tableName, "key" => $keyName ];
        return $this->sendCmd($cmd);
    }
    public function setKey($tableName, $keyName, $content) {
        $cmd = [ "cmd" => "setkey", "table" => $tableName, "key" => $keyName, "content" => $content ];
        return $this->sendCmd($cmd);
    }
    public function deleteKey($tableName, $keyName) {
        $cmd = [ "cmd" => "deletekey", "table" => $tableName, "key" => $keyName ];
        return $this->sendCmd($cmd);
    }
    public function queryAll($evaluator) {
        $cmd = [ "cmd" => "queryall", "evaluator" => $evaluator ];
        return $this->sendCmd($cmd);
    }
    public function getTables() {
        $cmd = [ "cmd" => "gettables" ];
        return $this->sendCmd($cmd);
    }
    public function queryTable($tableName, $evaluator) {
        $cmd = [ "cmd" => "querytable", "table" => $tableName, "evaluator" => $evaluator ];
        return $this->sendCmd($cmd);
    }
    public function tableExists($tableName) {
        $cmd = [ "cmd" => "tableexists", "table" => $tableName ];
        return $this->sendCmd($cmd);
    }
    public function tableSize($tableName) {
        $cmd = [ "cmd" => "tablesize", "table" => $tableName ];
        return $this->sendCmd($cmd);
    }
    public function tableKeys($tableName) {
        $cmd = [ "cmd" => "tablekeys", "table" => $tableName ];
        return $this->sendCmd($cmd);
    }
    public function getProperty($tableName, $keyName, $path) {
        $cmd = [ "cmd" => "getproperty", "table" => $tableName, "key" => $keyName, "path" => $path ];
        return $this->sendCmd($cmd);
    }
    public function setProperty($tableName, $keyName, $path, $value) {
        $cmd = [ "cmd" => "setproperty", "table" => $tableName, "key" => $keyName, "path" => $path, "value" => $value ];
        return $this->sendCmd($cmd);
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
            $chunk = $this->substring($send, $i*128, $i*128+128);
            echo $this->debug ? $chunk : "";
            array_push($tmp, $chunk);
        }
        foreach($tmp as $chunk) {
            if(!openssl_public_encrypt($chunk, $encrypted_data, $this->serverPub, OPENSSL_PKCS1_OAEP_PADDING)) {
                echo "{\"error\":\"Public Decryption Error\"}\n";
            }
            fwrite($this->socket, $encrypted_data);
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

    private function getKeyPair() {
        if(file_exists('.htprivkey.pem') && file_exists('clientcert.pem')) {
            echo $this->debug ? "Reading client keys from files..." : "";
            //Read client keys from files
            $fp=fopen(".htprivkey.pem", "r");
            $this->keypair['privateKey'] = fread($fp, 8192);
            fclose($fp);
            $fp = fopen("clientcert.pem", "r");
            $this->keypair['publicKey'] = fread($fp, 8192);
            fclose($fp);
            if($this-> keypair['privateKey'] == "" || $this-> keypair['privateKey'] == null) {
                //Private key blank, create new pair
                echo $this->debug ? "Private key is blank.\n" : "";
                $this->createKeyPair();
            }

            echo $this->debug ? "OK.\n" : "";
        } else {
            $this->createKeyPair();
        }
    }

    private function createKeyPair() {
        echo $this->debug ? "Creating new client keys..." : "";
        //Create the private and public key
        $ssl_type = [
            "digest_alg" => "sha512",
            "private_key_bits" => 4096,
            "private_key_type" => 'OPENSSL_KEYTYPE_RSA'
        ];
        $res = openssl_pkey_new($ssl_type);
        //Extract the private key from $res to $privKey
        openssl_pkey_export($res, $privKey);
        //Extract the public key from $res to $pubKey
        $pubKey = openssl_pkey_get_details($res);
        $pubKey = $pubKey["key"];
        //Write keys to files
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

    private function handshake() {
        echo $this->debug ? "Reading response:\n\n" : "";
        //Get public key from server
        $this->serverPub = fread($this->socket, 1024);

        echo $this->debug ? $this->serverPub : "";

        echo $this->debug ? "Split message:\n\n" : "";
        //Split message into 128 byte chunks to encrypt and send to socket
        $this->writeEnc($this->keypair['publicKey']);

        echo $this->debug ? "Reading response:\n\n" : "";
        //Recive encrypted newline from server
        $response = fread($this->socket, 1024);

        echo $this->debug ? $this->response : "";

        //Decrypte message from server
        $decrypted = $this->getResponse($response);

        echo $this->debug ? $decrypted : "";

        return $decrypted;
    }

    private function openSocket() {
        echo $this->debug ? "Attempting to connect to '$this->host' on port '$this->port'..." : "";
        //Open TCP/IP socket with HData server
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