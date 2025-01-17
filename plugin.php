<?php

defined('PASSWORDS_USER') || define('PASSWORDS_USER', 'username');
defined('PASSWORDS_PASS') || define('PASSWORDS_PASS', 'password');


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
          `label` varchar(255) COLLATE utf8_unicode_ci NULL,
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
  $db_info = getPlugin('passwords');
  $v1 = $db_info['db_version'];
  $code_info = plugin_passwords_info();
  $v2 = $code_info['version'];

  if ($v1 == $v2)
    throw new RackTablesError('Versions are identical', RackTablesError::INTERNAL);

  // find the upgrade path to be taken
  $versionhistory = array(
    '0.1',
    '0.2',
  );
  $skip = TRUE;
  $path = NULL;
  foreach ($versionhistory as $v) {
    if ($skip and $v == $v1) {
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
  if ($path === NULL or ! count($path))
    throw new RackTablesError('Unable to determine upgrade path', RackTablesError::INTERNAL);

  // build the list of queries to execute
  $queries = array();
  foreach ($path as $batchid) {
    switch ($batchid) {
      case '0.2':
        // perform some upgrade step here
        $queries[] = "ALTER TABLE `tpa_passwords` ADD `label` varchar(255) COLLATE utf8_unicode_ci NULL AFTER `entry_id`";
        $queries[] = "ALTER TABLE `tpa_passwords` ADD `secret` varchar(255) COLLATE utf8_unicode_ci NULL AFTER `password`";
        $queries[] = "UPDATE Plugin SET version = '0.2' WHERE name = 'passwords'";
        $refreshSecreets = true;
        break;
      default:
        throw new RackTablesError("Preparing to upgrade to {$batchid} failed", RackTablesError::INTERNAL);
    }
  }

  // execute the queries
  global $dbxlink;
  foreach ($queries as $q) {
    try {
      $result = $dbxlink->query($q);
    } catch (PDOException $e) {
      $errorInfo = $dbxlink->errorInfo();
      throw new RackTablesError("Query: {$errorInfo[2]}", RackTablesError::INTERNAL);
    }
  }

  if ($refreshSecreets) {
    $query = "
      SELECT
        k.id,
        k.entry_id,
        k.username,
        k.password
      FROM
        tpa_passwords k";

    //$ret = array();
    $result = usePreparedSelectBlade($query, $qparams);
    $array = $result->fetchAll(PDO::FETCH_ASSOC);

    foreach ($array as $key => $item) {
      $qparams = [
        pencrypt($item['username'], PASSWORDS_USER . $item['entry_id']),
        pencrypt($item['password'], PASSWORDS_PASS . $item['entry_id']),
        $item['id']
      ];

      usePreparedExecuteBlade(
        "
        UPDATE tpa_passwords
            SET
              username = ?,
              secret = ?
            WHERE id = ? AND secret is NULL",
        $qparams
      );
    }
  }
}


/* Register tab handlers and such */
function plugin_passwords_init() {
  global $ajaxhandler;
  global $tabhandler;
  global $tab;

  //$tabhandler['object']['password'] = 'showpassword'; // register a report rendering function
  $tab['object']['passwords'] = 'Passwords'; // title of the report tab
  $ajaxhandler['get-password-secret'] = 'plugin_passwords_secret';
  registerTabHandler('object', 'passwords', 'plugin_passwords_handler');
}

function plugin_passwords_secret() {
  recordPasswordsDebug('showpass_x found');

  $crsf = $_REQUEST['crsf'] ?? '';
  $crsf_id = pdecrypt($crsf, PASSWORDS_PASS . $_REQUEST['object_id']);
  $crsf_iv = $_REQUEST['object_id'] . '-' . $_REQUEST['labelid'];
  recordPasswordsDebug("CRSF: {$crsf}, CRSF_ID: {$crsf_id}, ENTRY_ID: {$crsf_iv}");
  $output = json_encode(['success' => false, 'reason' => 'security failure'], JSON_PRETTY_PRINT);
  if ($crsf_id == $crsf_iv) {
    $qparams = array($_REQUEST['object_id'], $_REQUEST['labelid']);
    $query = "
      SELECT
        k.id as Pid,
        k.entry_id,
        k.username,
        k.password,
        k.secret,
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
      AND k.id = ?
      AND k.hidden = 0;";

    //$ret = array();
    $result = usePreparedSelectBlade($query, $qparams);
    $items = $result->fetchAll(PDO::FETCH_ASSOC);
    $ret = [];
    foreach ($items as $item) {
      $ret = pdecrypt($item['secret'], PASSWORDS_PASS . $item['entry_id']);
      if ($ret !== null && $ret !== false) {
        $output = json_encode(['success' => true, 'password' => $ret], JSON_PRETTY_PRINT);
        break;
      }
    }
  }

  echo $output;
  return;
}

function plugin_passwords_handler() {
  global $remote_username;

  $object_id = intval($_REQUEST['object_id'] ?? 0);
  if ($object_id === 0) {
    header('Location: ' . $_SERVER['HTTP_REFERER'] . '');
    return;
  }

  if (isset($_POST['updpass_x'])) {
    // redirect to original page once query is executed
    header('Location: ' . $_SERVER['HTTP_REFERER'] . '');
    $qparms = [];
    $qparms['label'] = $_REQUEST['label'];
    $qparms['protocol'] = $_REQUEST['protocol'];
    $qparms['entry_id'] = $_REQUEST['object_id'];
    $qparms['username'] = pencrypt($_REQUEST['username'], PASSWORDS_USER . $object_id);
    if (!empty($_REQUEST['password'])) {
      $qparms['secret'] = pencrypt($_REQUEST['password'], PASSWORDS_PASS . $object_id);
    }
    $qparms['comment'] = $_REQUEST['comment'];

    $sql = "UPDATE tpa_passwords SET " . implode(" = ?,", array_keys($qparms)) . " = ? WHERE id = ?";
    $qparms[] = $_REQUEST['labelid'];

    return usePreparedExecuteBlade($sql, array_values($qparms));

    //echo print_r($_POST);
  }


  if (isset($_POST['addpass_x'])) {
    header('Location: ' . $_SERVER['HTTP_REFERER'] . '');
    $qparms = [
      $_REQUEST['label'],
      $_REQUEST['protocol'],
      pencrypt($_REQUEST['username'], PASSWORDS_USER . $object_id),
      pencrypt($_REQUEST['password'], PASSWORDS_PASS . $object_id),
      '',
      $_REQUEST['object_id'],
      date("Y-m-d H:i:s"),
      $remote_username,
      $_REQUEST['comment']
    ];

    return usePreparedExecuteBlade("
       INSERT INTO
         tpa_passwords(
           label,
           protocol,
           username,
           secret,
           password,
           entry_id,
           added,
           user_name,
           comment)
       VALUES(?,?,?,?,?,?,?,?,?)", $qparms);
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
      k.label,
      k.username,
      k.password,
      k.secret,
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

  $sorted = [];
  foreach ($array as $key => $item) {
    error_log('item ' . $key . ' = ' . json_encode($item));
    if (empty($item['secret'])) {
      $item['class'] = "password_show";
    } else {
      $username = pdecrypt($item['username'], PASSWORDS_USER . $item['entry_id']);
      //  For now, lets show the encrypted version to how we have failed to decrypt it
      if (!empty($username)) {
        $item['username'] = $username;
      }

      $item['password'] = '';
      $item['class'] = "password_secret";
      $item['crsf'] = pencrypt($item['entry_id'].'-'.$item['Pid'], PASSWORDS_PASS. $item['entry_id']);
    }

    $key = zKey($item['label'], $item['username'], $item['comment']);
    $sorted[strtolower($key)] = $item;
  }

  ksort($sorted);

addJS('https://code.jquery.com/jquery-3.3.1.min.js');
addJS('https://code.jquery.com/ui/1.12.1/jquery-ui.min.js');
addCSS('https://code.jquery.com/ui/1.12.1/themes/cupertino/jquery-ui.css');

?>
  <br>
  <div id="passwords_dialog"></div>
  <br>
  <table border="0" cellpadding="0" cellspacing="10" align="center">
<?php if (getConfigVar ('ADDNEW_AT_TOP') == 'yes') { ?>
    <tr>
      <td>&nbsp;</td>
      <td>Label</td>
      <td>Username</td>
      <td>Password</td>
      <td>&nbsp;</td>
      <td>Protocol</td>
      <td>Comment</td>
      <td>&nbsp;</td>
    </tr>
    <form method="post" name="pass-add" autocomplete=off action="" style="display: inline;">
    <tr>
      <td><INPUT type="image" name="addpass" value="" src="pix/tango-list-add.png"></td>
      <td><input type="text" name="label" value=""></td>
      <td><input type="text" name="username" value=""></td>
      <td><input type="text" name="password" value=""></td>
      <td>&nbsp;</td>
      <td><input type="text" name="protocol" value=""></td>
      <td><input type="text" name="comment" value=""></td>
      <td><INPUT type="image" name="addpass" value="" src="pix/tango-list-add.png"></td>
    </tr>
    <input type="hidden" name="labelid" value=''>
    </form>
    <tr>
      <td height="20"></td>
    </tr>
    <?php
}

    foreach ($sorted as $key => $item) {
	error_log('item ' . $key . ' = ' . json_encode($item));
    ?>
      <form method="post" name="pass-<?= $item['Pid'] ?>" id="pass-<?= $item['Pid'] ?>" autocomplete=off action="" data-object-id="<?= $item['entry_id']?>" data-label-id="<?= $item['Pid']?>" data-crsf="<?=$item['crsf']?>">
        <!-- ok its a dirty work around, but at least it will prevent the passwords from deleting when hitting enter -->
        <INPUT form="pass-<?= $item['Pid'] ?>" type="image" name="updpass" value="updpass" style="position: absolute; left: -9999px; width: 1px; height: 1px;" />
        <!-- and here another dirty work around, but this time from Chrome. -->
        <!-- it seems that chrome ignores autocomplete, yes...it ignores it, as workaround i have created an fake text & password field -->
        <!-- don't we just love standards....oh wait... -->
        <input form="pass-<?= $item['Pid'] ?>" type="text" name="prevent_autofill" id="prevent_autofill_<?= $item['Pid'] ?>" value="" style="display:none;" />
        <input form="pass-<?= $item['Pid'] ?>" type="password" name="password_fake" id="password_fake_<?= $item['Pid'] ?>" value="" style="display:none;" />
        <!-- end of dirty work around. -->
        <tr>
          <td><INPUT form="pass-<?= $item['Pid'] ?>" type="image" name="delpass" value="" src="pix/tango-list-remove.png"></td>
          <td><input form="pass-<?= $item['Pid'] ?>" type="text" name="label" value="<?= htmlspecialchars($item['label'], ENT_QUOTES, 'UTF-8'); ?>"></td>
          <td><input form="pass-<?= $item['Pid'] ?>" type="text" name="username" value="<?= htmlspecialchars($item['username'], ENT_QUOTES, 'UTF-8'); ?>"></td>
          <td><input form="pass-<?= $item['Pid'] ?>" type="password" name="password" value="<?= htmlspecialchars($item['password'], ENT_QUOTES, 'UTF-8'); ?>" class="<?= $item['class'] ?>"></td>
          <td><INPUT form="pass-<?= $item['Pid'] ?>" type="image" name="copypass" value="" class="copypass" src="pix/tango-edit-copy-16x16.png"></td>
          <td><input form="pass-<?= $item['Pid'] ?>" type="text" name="protocol" value="<?= htmlspecialchars($item['protocol'], ENT_QUOTES, 'UTF-8'); ?>"></td>
          <td><input form="pass-<?= $item['Pid'] ?>" type="text" name="comment" value="<?= htmlspecialchars($item['comment'], ENT_QUOTES, 'UTF-8'); ?>"></td>
          <td><INPUT form="pass-<?= $item['Pid'] ?>" type="image" name="updpass" value="" src="pix/tango-document-save-16x16.png"></td>
        </tr>
        <input form="pass-<?= $item['Pid'] ?>" type="hidden" name="labelid" value='<?= $item['Pid'] ?>'>
      </form>
    <?php
    }
    ?>
  </table>
  <script>
    $('.password_show').on('click', function(e) {
      e.preventDefault();
      e.stopPropagation();

      $(this).attr('type', 'text');
    });

    $(".password_show").on('blur', function(e) {
      e.preventDefault();
      e.stopPropagation();

      $(this).attr('type', 'password');
    });

    $('.copypass').on('click', function(e) {
      e.preventDefault();
      e.stopPropagation();

      var passwordForm = $(this.form)[0];
      var passwordFieldName = 'input[name=password][form=' + passwordForm.name + ']';
      var passwordField = $(passwordFieldName);
      var passwordValue = "";
      var passwordItem = null;

      if (passwordField.length) {
        passwordValue = passwordField[0].value;
      }

      if (!passwordValue.length) {
        var object_id = $(passwordForm).data('objectId');
        var label_id = $(passwordForm).data('labelId');
        var crsf = $(passwordForm).data('crsf');

        passwordItem = new ClipboardItem({
          'text/plain': new Promise(async (resolve) => {
            var result = await $.getJSON(
              window.location.pathname,
              {
                module: 'ajax',
                ac: 'get-password-secret',
                page: 'object',
                tab: 'passwords',
                object_id: object_id,
                labelid: label_id,
                crsf: crsf
              }
            );

            if (result.success) {
              resolve(new Blob([result.password], { type: 'text/plain' }));
            }
          }),
        });
      } else {
        passwordItem = new ClipboardItem({"text/plain": passwordValue});
      }

      navigator.clipboard.write([passwordItem]);

      var password_overlay = 'position:absolute;' +
        'top:0%;' +
        'left:50%;' +
        'background-color:beige;' +
        'color: black;' +
        'z-index:1002;' +
        'overflow:auto;' +
        'width: 10uw;' +
        'font-size: 1.5em;' +
        'border: 1px solid black;' +
        'text-align:center;' +
        'margin: auto 0;';

      var password_div = $('#password_count');
      var password_count = 10;
      if (password_div.length == 0) {
        $('body').append('<div id="password_count" style="' + password_overlay + '"><div id="password_time"></div></div>');
      }

      $('#password_count').show();
      var password_timer = setInterval(function () {
        $("#password_time").html("Clearing password in " + password_count + " second(s)");
        password_count = (password_count - 1);

        if (password_count < 0)
        {
            clearInterval(password_timer);
            $("#password_count").hide();
        }
      }, 1000);

      navigator.clipboard.write([
        new ClipboardItem({
          'text/plain': new Promise(async (resolve) => {
            await new Promise(r => setTimeout(r, 10000));
            resolve(new Blob([''], { type: 'text/plain' }));
          })
        })
      ]);
    });

    $('.copypassold').on('click', function(e) {
      e.preventDefault();
      e.stopPropagation();

      var passwordForm = $(this.form)[0];
      var passwordFieldName = 'input[name=password][form=' + passwordForm.name + ']';
      var passwordField = $(passwordFieldName);
      var passwordValue = "";

      if (passwordField.length) {
        passwordValue = passwordField[0].value;
      }

      if (!passwordValue.length) {
        var object_id = $(passwordForm).data('objectId');
        var label_id = $(passwordForm).data('labelId');

        $.getJSON(
          window.location.pathname,
          {
            module: 'ajax',
            ac: 'get-password-secret',
            page: 'object',
            tab: 'passwords',
            object_id: object_id,
            labelid: label_id
          }
        ).done(function(result) {
          debugger;
          if (result.success) {
            copyPasswordToClipboard(result.password);
          }
        }).fail(function() {
          alert("Failed to retrieve password");
        }).always(function() {
          //ajaxUIUnlock();
        });
      } else {
        copyPasswordToClipboard(passwordValue);
      }
    });

    var alertPasswordTimeout = null;
    var clearPasswordTimeout = null;
    function copyPasswordToClipboard(passwordValue) {
      if (typeof passwordValue !== 'undefined' && passwordValue.length) {
        if (alertPasswordTimeout != null) {
          clearTimeout(alertPasswordTimeout);
        }

        if (clearPasswordTimeout != null) {
          clearTimeout(clearPasswordTimeout);
        }

        try {
          navigator.clipboard.writeText(passwordValue);
          alertPasswordTimeout = setTimeout(alertPassword, 300);
        } catch (ex) {
          ;
        }
      }
    }

    function alertPassword() {
      if (alertPasswordTimeout != null) {
        clearTimeout(alertPasswordTimeout);
      }

      alert("Password copied, click OK to clear and continue...");

      clearPasswordTimeout = setTimeout(clearPassword, 1000);
    }

    function clearPassword() {
      try {
        navigator.clipboard.writeText("");
      } catch (ex) {
        ;
      }
    }
  </script>
<?php
}

function pencrypt($message, $key = null, $cipher = "AES-128-CBC", $as_binary = true, $options = OPENSSL_RAW_DATA) {
  // Generate a random encryption key
  $key ??= openssl_random_pseudo_bytes(16);
  if ($key === false) {
    recordPasswordsDebug('pencrypt(): failed openssl_random_pseudo_bytes (key)');
    return null;
  }

  // Encrypt the message using AES-128-CBC encryption
  $ivlen = openssl_cipher_iv_length($cipher);
  if ($ivlen === false) {
    recordPasswordsDebug('pencrypt(): failed openssl_cipher_iv_length');
    return null;
  }

  $iv = openssl_random_pseudo_bytes($ivlen);
  if ($iv === false) {
    recordPasswordsDebug('pencrypt(): failed openssl_random_pseudo_bytes (iv)');
    return null;
  }

  recordPasswordsDebug('pencrypt() key = [' . $key . ']');
  $ciphertext_raw = openssl_encrypt($message, $cipher, $key, $options, $iv);
  if ($ciphertext_raw === false) {
    recordPasswordsDebug('pencrypt(): failed openssl_encrypt');
    return null;
  }

  $hmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary);
  if ($hmac === false) {
    recordPasswordsDebug('pencrypt(): failed hash_hmac');
    return null;
  }

  recordPasswordsBytes('pencrypt() iv', $iv);
  recordPasswordsBytes('pencrypt() hmac', $hmac);
  recordPasswordsBytes('pencrypt() ciphertext_raw', $ciphertext_raw);

  $ciphertext = base64_encode($iv . $hmac . $ciphertext_raw);
  recordPasswordsDebug('pencrypt() ciphertext_b64 = [' . $ciphertext . ']');
  if ($ciphertext === false) {
    recordPasswordsDebug('pencrypt(): failed base64_encode was false');
    return null;
  } else {
    return $ciphertext;
  }
}

function pdecrypt($ciphertext, $key, $cipher = "AES-128-CBC", $as_binary = true, $options = OPENSSL_RAW_DATA) {
  $c = base64_decode($ciphertext);
  if ($c === false) {
    recordPasswordsDebug('pdecrypt(): failed base64_decode');
    return null;
  }

  $ivlen = openssl_cipher_iv_length($cipher);
  if ($ivlen === false) {
    recordPasswordsDebug('pdecrypt(): failed openssl_cipher_iv_length');
    return null;
  }

  $iv = substr($c, 0, $ivlen);
  if ($iv === false) {
    recordPasswordsDebug('pdecrypt(): failed substr#1');
    return null;
  }

  $hmac = substr($c, $ivlen, $sha2len = 32);
  if ($hmac === false) {
    recordPasswordsDebug('pdecrypt(): failed substr#2');
    return null;
  }

  $ciphertext_raw = substr($c, $ivlen + $sha2len);
  if ($ciphertext_raw === false) {
    recordPasswordsDebug('pdecrypt(): failed substr#3');
    return null;
  }

  recordPasswordsDebug('pdecrypt() key = [' . $key . ']');
  recordPasswordsBytes('pdecrypt() iv', $iv);
  recordPasswordsBytes('pdecrypt() hmac', $hmac);
  recordPasswordsBytes('pdecrypt() ciphertext_raw', $ciphertext_raw);
  recordPasswordsDebug('pdecrypt() ciphertext_b64 = [' . $key . ']');

  $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options, $iv);
  recordPasswordsDebug('pdecrypt(): key = [' . $key . ']');
  if ($original_plaintext === false) {
    recordPasswordsDebug('pdecrypt(): failed openssl_decrypt');
    return null;
  }

  $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary);
  if ($calcmac === false) {
    recordPasswordsDebug('pdecrypt(): failed hash_hmac');
    return null;
  } elseif (hash_equals($hmac, $calcmac)) {
    return $original_plaintext;
  } else {
    recordPasswordsDebug('pdecrypt(): failed hash_equals');
    return null;
  }
}

function isPasswordsDebugUser() {
  global $remote_username;

  return $remote_username == 'admin';
}

function recordPasswordsBytes($prefix, $value) {
  $byte_string = '';
  for ($i = 0; $i < strlen($value); $i++) {
    $byte_string .= dechex(ord($value[$i])) . ' ';
  }

//  recordPasswordsDebug($prefix . ' = [' . rtrim($byte_string) . ']');
}

function recordPasswordsDebug($message) {
  if (isPasswordsDebugUser()) {
    error_log("PASSWORDS: " . $message);
  }
}

function zKey(...$keys) {
  $output = '';
  foreach ($keys as $key) {
    $output .= (empty($output) ? '' : '__') .  (empty($key) ? '||' : $key);
  }

  return $output;
}
