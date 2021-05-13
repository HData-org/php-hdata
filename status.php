<?php

header('Content-Type: application/json');

require('src/HData.php');

use HData\HData;

$host = "flolon.cc";
$port = 8888;

$hdata = new HData\HData($host, $port, true);

echo $hdata->getStatus();

$hdata->disconnect();
