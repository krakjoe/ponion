<?php
class Query extends OnionQuery {
	public function __construct() {
		global $_GET;
		
		if (!$_GET instanceof Query) {
			$_GET = $this;
		}
	}
}

class Request extends Query {
	public function __construct() {
		global $_REQUEST;
		
		parent::__construct();
		if (!$_REQUEST instanceof Request) {
			$_REQUEST = $this;
		}
	}
}

class Post extends OnionPost {
	public function __construct() {
		global $_POST;
		
		if (!$_POST instanceof Post) {
			$_POST = $this;
		}
	}
}

new Post();
new Query();
new Request();

echo "<pre>";
var_dump($_GET, $_POST, $_COOKIES, $_REQUEST);
var_dump($_REQUEST["third"]);
var_dump($_POST["posted"]);
$headers = new OnionHeaders();
var_dump($headers, $headers["accept"]);
echo "</pre>";
?>
<form action="" method="post">
<textarea name="posted"><?=$_POST["posted"]; ?></textarea>
<input type="submit"/>
</form>
