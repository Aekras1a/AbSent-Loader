<?php
$dbhost = ""; 		// The host of your database
$dbuser = ""; 			// The database username
$dbpass = ""; 	// The database password
$dbname = ""; 		// The database name

$rc4Key = "AAAA";

//$odb = new PDO("mysql:host=$dbhost;dbname=$dbname", $dbuser, $dbpass);

function loggedIn($odb)
{
	if (isset($_SESSION['AbSent']))
	{
		$usern = $_SESSION['AbSent'];
		if ($usern == "" || $usern == NULL)
		{
			return false;
		}
		else
		{
			$user = explode(":", $usern);
			if (!ctype_alnum($user[0]))
			{
				return false;
			}
			else
			{
				if ($odb->query("SELECT COUNT(*) FROM users WHERE username = '".$user[0]."'")->fetchColumn(0) == 0)
				{
					return false;
				}
				else
				{
					$sel = $odb->query("SELECT * FROM users WHERE username = '".$user[0]."'");
					$u = $sel->fetch(PDO::FETCH_ASSOC);
					if ($u['id'] != $user[1])
					{
						return false;
					}
					else
					{
						if ($u['status'] == "1")
						{
							return true;
						}
						else
						{
							return false;
						}
					}
				}
			}
		}
	}
	else
	{
		return false;
	}
}
?>