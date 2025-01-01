<?php

/* "The question is: Who... are you?" */
function plugin_passwords_info() {
  return array(
    'name'     => "passwords",
    'longname' => "Passwords Tab",
    'version'  => "0.2",
    'home_url' => ''
  );
}

/* Get the party started */
function plugin_passwords_install() {
  return usePreparedExecuteBlade("
        CREATE TABLE IF NOT EXISTS `tpa_passwords` (
        `id` int(11) NOT NULL AUTO_INCREMENT,
          `protocol` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
          `entry_id` int(11) NOT NULL,
          `username` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
          `password` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
          `secret` varchar(255) COLLATE utf8_unicode_ci NULL,
          `comment` text COLLATE utf8_unicode_ci NOT NULL,
          `added` datetime NOT NULL,
          `deleted` datetime NULL,
          `user_name` text COLLATE utf8_unicode_ci NOT NULL,
          `hidden` int(1) DEFAULT '0',
          PRIMARY KEY (`id`)
        )  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=1;
    ");
}

/* Remove plugin so it can't hurt anyone */
function plugin_passwords_uninstall() {
  // return usePreparedExecuteBlade("DROP TABLE IF EXISTS `tpa_passwords`");
  return true;
}

/* Upgrade plugin */
function plugin_passwords_upgrade() {
	$db_info = getPlugin ('passwords');
	$v1 = $db_info['db_version'];
	$code_info = plugin_plugin_info ();
	$v2 = $code_info['version'];

	if ($v1 == $v2)
		throw new RackTablesError ('Versions are identical', RackTablesError::INTERNAL);

	// find the upgrade path to be taken
	$versionhistory = array
	(
		'0.1',
		'0.2',
	);
	$skip = TRUE;
	$path = NULL;
	foreach ($versionhistory as $v)
	{
		if ($skip and $v == $v1)
		{
			$skip = FALSE;
			$path = array();
			continue;
		}
		if ($skip)
			continue;
		$path[] = $v;
		if ($v == $v2)
			break;
	}
	if ($path === NULL or ! count ($path))
		throw new RackTablesError ('Unable to determine upgrade path', RackTablesError::INTERNAL);

	// build the list of queries to execute
	$queries = array ();
	foreach ($path as $batchid)
	{
		switch ($batchid)
		{
			case '0.2':
				// perform some upgrade step here
        $queries[] = "ALTER TABLE `tpa_passwords` ADD `secret` varchar(255) COLLATE utf8_unicode_ci NULL";
				$queries[] = "UPDATE Plugin SET version = '0.2' WHERE name = 'passwords'";
        $refreshSecreets = true;
				break;
			default:
				throw new RackTablesError ("Preparing to upgrade to {$batchid} failed", RackTablesError::INTERNAL);
		}
	}

	// execute the queries
	global $dbxlink;
	foreach ($queries as $q)
	{
		try
		{
			$result = $dbxlink->query ($q);
		}
		catch (PDOException $e)
		{
			$errorInfo = $dbxlink->errorInfo();
			throw new RackTablesError ("Query: {$errorInfo[2]}", RackTablesError::INTERNAL);
		}
	}

  if ($refreshSecreets) {
    $qparams = array($_REQUEST['object_id']);
    $query = "
      SELECT
        k.id,
        k.entry_id,
        k.username,
        k.password
      FROM
        tpa_passwords k
      LEFT JOIN
        Object o
      ON
        k.entry_id=o.id
      WHERE
        o.id = ?
      AND k.hidden = 0;";

    //$ret = array();
    $result = usePreparedSelectBlade($query, $qparams);
    $array = $result->fetchAll(PDO::FETCH_ASSOC);

    foreach ($array as $key => $item) {
      $qparams = [
        pencrypt($item['username'], 'username' . $item['entry_id']),
        pencrypt($item['password'], 'password' . $item['entry_id']),
        $item['id']
      ];

      usePreparedExecuteBlade("
        UPDATE tpa_passwords
            SET
              username = ?,
              secret = ?,
            WHERE id = ? AND secret is NULL",
      $qparams);
    }
  }
}


/* Register tab handlers and such */
function plugin_passwords_init() {
  global $tabhandler;
  global $tab;

  //$tabhandler['object']['password'] = 'showpassword'; // register a report rendering function
  $tab['object']['passwords'] = 'Passwords'; // title of the report tab
  registerTabHandler('object', 'passwords', 'showpassword');
}
#$tabhandler['object']['password'] = 'showpassword'; // register a report rendering function
#$tab['object']['password'] = 'Passwords'; // title of the report tab


function showpassword() {
  global $remote_username;

  $object_id = intval($_REQUEST['object_id'] ?? 0);
  if ($object_id === 0) {
    header('Location: ' . $_SERVER['HTTP_REFERER'] . '');
    return;
  }

  if (isset($_POST['updpass_x'])) {
    // redirect to original page once query is executed
    header('Location: ' . $_SERVER['HTTP_REFERER'] . '');
    $qparms = [
      $_REQUEST['protocol'],
      $_REQUEST['object_id'],
      pencrypt($_REQUEST['username'], 'username' . $object_id),
      pencrypt($_REQUEST['password'], 'password' . $object_id),
      $_REQUEST['comment'],
      $_REQUEST['labelid'],
    ];
    return usePreparedExecuteBlade("
      UPDATE tpa_passwords
          SET
            protocol = ?,
            entry_id = ?,
            username = ?,
            password = ?,
            comment  = ?
          WHERE id = ?", $qparms);

    //echo print_r($_POST);
  }


  if (isset($_POST['addpass_x'])) {
    header('Location: ' . $_SERVER['HTTP_REFERER'] . '');
    $qparams = [
      $_REQUEST['protocol'],
      pencrypt($_REQUEST['username'],'username' . $object_id),
      pencrypt($_REQUEST['password'],'password' . $object_id),
      $_REQUEST['object_id'],
      date("Y-m-d H:i:s"),
      $remote_username,
      $_REQUEST['comment']
    ];

    return usePreparedExecuteBlade("
       INSERT INTO
         tpa_passwords(
           protocol,
           username,
           password,
           entry_id,
           added,
           user_name,
           comment)
       VALUES(?,?,?,?,?,?,?)", $qparms);
  }

  if (isset($_POST['delpass_x'])) {
    header('Location: ' . $_SERVER['HTTP_REFERER'] . '');
    return usePreparedExecuteBlade("
     UPDATE tpa_passwords
       SET
       hidden = 1,
       deleted = '" . date("Y-m-d H:i:s") . "'
       WHERE id = '" . $_REQUEST['labelid'] . "'");
    // echo "Deleted";
    // echo print_r($_POST);
  }

  $qparams = array($_REQUEST['object_id']);
  $query = "
    SELECT
      k.id as Pid,
      k.entry_id,
      k.username,
      k.password,
      k.comment,
      k.protocol,
      o.id
    FROM
      tpa_passwords k
    LEFT JOIN
      Object o
    ON
      k.entry_id=o.id
    WHERE
      o.id = ?
    AND k.hidden = 0;";

  //$ret = array();
  $result = usePreparedSelectBlade($query, $qparams);
  $array = $result->fetchAll(PDO::FETCH_ASSOC);

  echo "
   <br>
   <br>
   <table border=\"0\" cellpadding\"0\" cellspacing\"10\" align=\"center\">
     <tr>
       <td>&nbsp;</td>
       <td>Username</td>
       <td>Password</td>
       <td>Protocol</td>
       <td>Comment</td>
       <td>&nbsp;</td>
       ";
  echo "<form method=\"post\" name=\"pass-add\" autocomplete=off action=\"\" style=\"display: inline;\">";
  echo "  <tr>";
  echo "    <td><INPUT type=\"image\"      name=\"addpass\" value=\"\" src=\"pix/tango-list-add.png\"></td>";
  echo "    <td><input type=\"text\"       name=\"username\" value=\"\"></td>";
  echo "    <td><input type=\"text\"       name=\"password\" value=\"\"></td>";
  echo "    <td><input type=\"text\"       name=\"protocol\" value=\"\"></td>";
  echo "    <td><input type=\"text\"       name=\"comment\"  value=\"\"></td>";
  echo "    <td><INPUT type=\"image\"      name=\"addpass\"  value=\"\" src=\"pix/tango-list-add.png\"></td>";
  echo "  </tr>";
  echo "<input type=\"hidden\" name=\"labelid\"    value=''>";
  echo "</form>";
  echo "<tr><td height=\"20\"></td></tr>";

  foreach ($array as $key => $item) {
    // echo $array[$key]['id'];
    echo "<form method=\"post\" name=\"pass-" . $array[$key]['Pid'] . " \"autocomplete=off action=\"\">";
    // ok its a dirty work around, but at least it will prevent the passwords from deleting when hitting enter
    echo "  <INPUT type=\"image\" name=\"updpass\"  value=\"updpass\" style=\"position: absolute; left: -9999px; width: 1px; height: 1px;\"/>";
    // and here another dirty work around, but this time from Chrome.
    // it seems that chrome ignores autocomplete, yes...it ignores it, as workaround i have created an fake text & password field
    // don't we just love standards....oh wait...
    echo "   <input type=\"text\" name=\"prevent_autofill\" id=\"prevent_autofill\" value=\"\" style=\"display:none;\" />";
    echo "   <input type=\"password\" name=\"password_fake\" id=\"password_fake\" value=\"\" style=\"display:none;\" />";
    // end of dirty work around.
    echo "  <tr>";
    echo "    <td><INPUT type=\"image\"      name=\"delpass\"  value=\"\" src=\"pix/tango-list-remove.png\"></td>";
    echo "    <td><input type=\"text\"       name=\"username\" value=\"" . pdecrypt($item['username'], 'username' . $item['object_id']) . "\"></td>";
    echo "    <td><input type=\"password\"   name=\"password\" value=\"\"><INPUT type=\"image\" name=\"copypass\"  value=\"\" src=\"pix/tango-edit-copy-16x16.png\"></td>";
    echo "    <td><input type=\"text\"       name=\"protocol\" value=\"" . $item['protocol'] . "\"></td>";
    echo "    <td><input type=\"text\"       name=\"comment\"  value=\"" . $item['comment'] . "\"></td>";
    echo "    <td><INPUT type=\"image\"      name=\"updpass\"  value=\"\" src=\"pix/tango-document-save-16x16.png\"></td>";
    echo "  </tr>";
    echo "<input type=\"hidden\" name=\"labelid\"    value='" . $item['Pid'] . "'>";
    echo "</form>";
  }
  echo "</table>";
}

function pencrypt($message, $key, $cipher = "AES-128-CBC", $as_binary = true, $options = OPENSSL_RAW_DATA) {
  // Generate a random encryption key
  $key = openssl_random_pseudo_bytes(16);
  if ($key === false) {
    return null;
  }

  // Encrypt the message using AES-128-CBC encryption
  $ivlen = openssl_cipher_iv_length($cipher);
  if ($ivlen === false) {
    return null;
  }

  $iv = openssl_random_pseudo_bytes($ivlen);
  if ($iv === false) {
    return null;
  }

  $ciphertext_raw = openssl_encrypt($message, $cipher, $key, $options, $iv);
  if ($ciphertext_raw === false) {
    return null;
  }

  $hmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary);
  if ($hmac === false) {
    return null;
  }

  $ciphertext = base64_encode($iv . $hmac . $ciphertext_raw);
  if ($ciphertext === false) {
    return null;
  } else {
    return $ciphertext;
  }
}

function pdecrypt($ciphertext, $key, $cipher = "AES-128-CBC", $as_binary = true, $options = OPENSSL_RAW_DATA) {
  $c = base64_decode($ciphertext);
  if ($c === false) {
    return null;
  }

  $ivlen = openssl_cipher_iv_length($cipher);
  if ($ivlen === false) {
    return null;
  }

  $iv = substr($c, 0, $ivlen);
  if ($iv === false) {
    return null;
  }

  $hmac = substr($c, $ivlen, $sha2len = 32);
  if ($hmac === false) {
    return null;
  }

  $ciphertext_raw = substr($c, $ivlen + $sha2len);
  if ($ciphertext_raw === false) {
    return null;
  }

  $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options, $iv);
  if ($original_plaintext === false) {
    return null;
  }

  $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary);
  if ($calcmac === false) {
    return null;
  } elseif (hash_equals($hmac, $calcmac)) {
    return $original_plaintext;
  } else {
    return null;
  }
}
