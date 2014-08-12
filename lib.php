<?php
namespace kistriver\libs\sso;
class Server
{
	const VER = 1;

	protected $id;
	protected $key;
	protected $redirect_to;
	protected $redirect_from;
	protected $token;
	protected $token_expired;
	protected $sig;
	protected $data = [];

	public function __construct($p = [])
	{
		$this->id = isset($_GET['id'])?$_GET['id']:null;
		$this->redirect_to = isset($_GET['redirect_to'])?$_GET['redirect_to']:'about:blank';
		$this->redirect_from = isset($_GET['redirect_from'])?$_GET['redirect_from']:'about:blank';
		$this->token = isset($_GET['token'])?$_GET['token']:'';
		$this->token_expired = isset($p['token_expired'])?$p['token_expired']:2;
		$this->sig = isset($_GET['sig'])?$_GET['sig']:'';
		$this->data = isset($p['data'])?$p['data']:[];

		$this->setConnection();

		if($this->token=='')
		{
			$this->setToken();
			$this->redirect();
		}
		else
		{
			$this->getInfo();
		}
	}

	public function __get($name)
	{
		if(property_exists($this, $name))
			return $this->$name;

		throw new \Exception('Undefined property');
	}

	protected function setConnection()
	{
		if(preg_match("'[^0-9]'is", $this->id))throw new \Exception('Broken ID');

		$cons =
			[
				'1'=>['secretKEY']
			];

		if(isset($cons[$this->id]))
		{
			$c = $cons[$this->id];

			$this->key = $c[0];
		}
		else
			throw new \Exception('Undefined ID');
	}

	protected function setToken()
	{
		$token_dict = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
		for($i=0;$i<16;$i++)
			$this->token .= $token_dict[rand(0,15)];

		$db = json_decode(file_get_contents(dirname(__FILE__).'/db.json'),true);
		$db[$this->token] = [microtime(true), $this->id, $this->data];
		file_put_contents(dirname(__FILE__).'/db.json',json_encode($db));
	}

	protected function getToken()
	{
		$db = json_decode(file_get_contents(dirname(__FILE__).'/db.json'),true);
		if(!isset($db[$this->token]))
		{
			//throw new \Exception('Token not found');
			return false;
		}

		$data = $db[$this->token];

		if($data[1]!=$this->id)
		{
			//throw new \Exception('Wrong ID');
			return false;
		}

		if($data[0]+$this->token_expired<microtime(true))
		{
			return false;
		}

		$this->data = $data[2];
	}

	protected function getInfo()
	{
		if($this->sig!=$this->signature($this->token))
			$this->output(['error'=>[0,'wrong signature']]);

		if($this->getToken()===false)
			$this->output(['error'=>[1,'token expired']]);

		$this->output();
	}

	public function signature($string)
	{
		return sha1($this->key.$string);
	}

	public function addHttpQueryChar($link)
	{
		return preg_match("'\?'is",$link)===0?'?':'&';
	}

	public function addHttpP(&$link, $p = [])
	{
		foreach($p as $k=>$v)
			$link .= $this->addHttpQueryChar($link).urlencode($k).'='.urlencode($v);

		return $link;
	}

	protected function redirect()
	{
		if($this->sig==$this->signature($this->redirect_from))
		{
			$this->location($this->addHttpP($this->redirect_to,
				['token'=>$this->token,
					'redirect_from'=>$this->redirect_from,
					'sig'=>$this->signature($this->token.$this->redirect_from)]));
		}
		else
		{
			echo "Redirect failed: wrong signature";
		}
	}

	public function location($l)
	{
		//echo "Location: <a href='$l'>$l</a><br />\r\n";
		header('Location: '.$l);
	}

	public function output($p = [])
	{
		$p['data'] = $this->data;
		echo json_encode($p, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
		exit;
	}
}



class Consumer
{
	const VER = 1;

	protected $id;
	protected $key;
	protected $redirect_hosts = [];
	protected $redirect_to;
	protected $redirect_self;
	protected $redirect_from;
	protected $token;
	protected $sig;
	protected $info;

	public function __construct($p = [])
	{
		$this->id = isset($p['id'])?$p['id']:null;
		$this->key = isset($p['key'])?$p['key']:'';
		$this->redirect_hosts = isset($p['redirect_hosts'])?$p['redirect_hosts']:[];
		$this->redirect_to = isset($p['redirect_to'])?$p['redirect_to']:'';
		$this->redirect_self = isset($p['redirect_self'])?$p['redirect_self']:'';
		$this->redirect_from = isset($_GET['redirect_from'])?$_GET['redirect_from']:
			(isset($_SERVER['HTTP_REFERER'])?$_SERVER['HTTP_REFERER']:
				('http'.($_SERVER['HTTPS']?'s':'').'://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']));
		$this->token = isset($_GET['token'])?$_GET['token']:'';
		$this->sig = isset($_GET['sig'])?$_GET['sig']:'';

		if($this->token=='')
		{
			$this->getToken();
		}
		else
		{
			$this->getInfo();
			$this->setInfo();
		}
	}

	protected function getToken()
	{
		if(!$this->allowedRedirect($this->redirect_from))$this->location('about:blank');
		else $this->location($this->addHttpP($this->redirect_to,[
			'id'=>$this->id,
			'redirect_to'=>$this->redirect_self,
			'redirect_from'=>$this->redirect_from,
			'sig'=>$this->signature($this->redirect_from),
		]));
	}

	protected function getInfo()
	{
		if($this->sig!=$this->signature($this->token.$this->redirect_from))
		{
			echo "Get info failed: wrong signature";
			return;
		}

		$opts = ['http'=>['method'=>'GET','header'=>
		'Authorization: Basic '.base64_encode('')."\r\n"
		]];
		$j = file_get_contents($this->addHttpP($this->redirect_to,[
			'id'=>$this->id,
			'token'=>$this->token,
			'sig'=>$this->signature($this->token),
		]),null,stream_context_create($opts));
		if($j===false)
			throw new \Exception('Could not connect to center');

		$info = json_decode($j,true);
		if(json_last_error()!==JSON_ERROR_NONE)
			throw new \Exception('Could not decode data');

		$this->info = $info;
	}

	protected function setInfo()
	{
		if(isset($this->info['error']))
		{
			if(sizeof($this->info['error'])!=0)
			{
				echo "{$this->info['error'][1]} #{$this->info['error'][0]}";
			}
		}
		elseif(isset($this->info['data']))
		{
			if(sizeof($this->info['data'])!=0)
			{
				$_SESSION['id_resource'] = $this->info['data']['id'];
			}
			else
			{
				$_SESSION['id_resource'] = 0;
			}
		}
		$this->location($this->redirect_from);
	}

	public function location($l)
	{
		//echo "Location: <a href='$l'>$l</a><br />\r\n";
		header('Location: '.$l);
	}

	public function signature($string)
	{
		return sha1($this->key.$string);
	}

	public function addHttpQueryChar($link)
	{
		return preg_match("'\?'is",$link)===0?'?':'&';
	}

	public function addHttpP(&$link, $p = [])
	{
		foreach($p as $k=>$v)
			$link .= $this->addHttpQueryChar($link).urlencode($k).'='.urlencode($v);

		return $link;
	}

	public function allowedRedirect($rd)
	{
		$rd = parse_url($rd);
		if(!isset($rd['host']))$rd['host'] = '';
		if(!isset($rd['scheme']))$rd['scheme'] = '';

		if(!in_array($rd['host'], $this->redirect_hosts))return false;
		if(!in_array($rd['scheme'], ['http','https']))return false;

		return true;
	}
}
