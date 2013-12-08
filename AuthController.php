<?

class AuthController extends Soway_Controller_Action
{
	public function init()
	{
		$this->_helper->viewRenderer->setNoRender(true);
       	$this->_helper->layout->disableLayout();
		parent::init();	
	}
	
	public function logoutAction()
	{
		Zend_Auth::getInstance()->clearIdentity();
		session_destroy();
		session_regenerate_id(true);
		$this->userInfo = null;
		$_SESSION = null;
		//the following logs the user out of facebook as well
		//$logoutUrl = Zend_Registry::get('fb')->getLogoutUrl(array('next' => 'http://'.$_SERVER['HTTP_HOST'].'/'));
		$this->_redirect('/');
	}
	
	public function linkedinAction()
	{
		$hUsers = new Soway_Users();
		
		$consumer_key = 'sgbfn7tjqy5o';
		$consumer_secret = 'HwTNcLd7k6vE21oW';
		$access_token_url = 'https://api.linkedin.com/uas/oauth/accessToken';
		$authenticated = false;
		
		if(!empty($_COOKIE["linkedin_oauth_".$consumer_key])){
			
			$credentials = json_decode($_COOKIE["linkedin_oauth_".$consumer_key]);
			
			if ($credentials->signature_version == 1) {
			    if ($credentials->signature_order && is_array($credentials->signature_order)) {
			        $base_string = '';
			        // build base string from values ordered by signature_order
			        foreach ($credentials->signature_order as $key) {
			            if (isset($credentials->$key)) {
			                $base_string .= $credentials->$key;
			            } else {
			                print "missing signature parameter: $key";
			            }
			        }
					
			        // hex encode an HMAC-SHA1 string
			        $signature =  base64_encode(hash_hmac('sha1', $base_string, $consumer_secret, true));
			        // check if our signature matches the cookie's
			        if ($signature == $credentials->signature) {
			            
						//linkedin auth success - add, or update user and then login
						
						$checkUser = $hUsers->getUserByLinkedinID($credentials->member_id);
						if(is_object($checkUser)){
							$authenticated = true;
						}
						
						$oauth = new OAuth($consumer_key, $consumer_secret);
						$access_token = $credentials->access_token;
						// swap 2.0 token for 1.0a token and secret
						$oauth->fetch($access_token_url, array('xoauth_oauth2_access_token' => $access_token), OAUTH_HTTP_METHOD_POST);
						// parse the query string received in the response
						parse_str($oauth->getLastResponse(), $response);
						
						$oauth->setToken($response['oauth_token'],$response['oauth_token_secret']);
						$url = 'http://api.linkedin.com/v1/people/~:(id,first-name,last-name,headline,industry,num-connections,summary,specialties,positions,picture-url,public-profile-url,email-address)';
						$oauth->fetch($url, array(), OAUTH_HTTP_METHOD_GET, array('x-li-format' => 'json')); // JSON!
						$profile = json_decode($oauth->getLastResponse());

						if(is_object($profile)){
							//TODO: update oauth tokens
							if($authenticated){
								$this->_auth->setIdentity($checkUser->username)  
            						        ->setCredential($checkUser->password);
							
								$select = $this->_auth->getDbSelect();
								$select->where('enabled = 1');
								$this->_auth->authenticate();
			  					$userInfo = $this->_auth->getResultRowObject(null, 'password');
								
								if($userInfo){
									//$userInfo->permissions = (int)$hUsers->getUserPermission($userid, 2);
									Zend_Auth::getInstance()->getStorage()->write($userInfo); 
								} else {
									$this->_redirect('/');
									return;
								}
							} else {
								$profile->access_token = $credentials->access_token;
								$profile->oauth_token  = $response["oauth_token"];
								$profile->oauth_secret = $response["oauth_token_secret"];
								
								$_SESSION["registration_li_profile"] = $profile;
								$this->_redirect('/?register=1');
								return;
							}
							
							
							
						}

			      	} else {
			            print "signature validation failed";    
			        }
			    } else {
			        print "signature order missing";
			    }
			} else {
			    print "unknown cookie version";
			}
			
		}
	}
	
	public function facebookAction()
	{
		$hUsers = new Soway_Users();
		$fb = Zend_Registry::get('fb');
		$authenticated = false;
		
		if($userid = $fb->getUser())
		{
			try{
				$user_profile = $fb->api('/me');
				
				if(!$user_profile || empty($user_profile['id'])){
					$this->_redirect('/');
						return;
				}
				
				$checkUser = $hUsers->getUserByFacebookID($user_profile['id']);
				
				if(is_object($checkUser)){
					$authenticated = true;
				}
				
				
				$username = $user_profile['username'];
				if(empty($username)){
					//some users wont have usernames
					$username = str_replace(' ', '', $user_profile['name']);
					$username = strtolower($username);
				};
				
				$userid = $hUsers->getOrCreateUser($user_profile['first_name'],
										 $user_profile['last_name'],
										 $username,
										 '',
										 $user_profile['email'],
										 $user_profile['id'],
										 $user_profile['gender']);
				
				$hUsers->setTimezoneOffset($userid, @$user_profile['timezone']);
				$hUsers->setFacebookToken($userid, $fb->getAccessToken());
				
				
				if($authenticated && $userid){
					$this->_auth->setIdentity($checkUser->username)  
            				->setCredential($checkUser->password);
							
					$select = $this->_auth->getDbSelect();
					$select->where('enabled = 1');
					$this->_auth->authenticate();
  					$userInfo = $this->_auth->getResultRowObject(null, 'password');
					
					if($userInfo){
						//$userInfo->permissions = (int)$hUsers->getUserPermission($userid, 2);
						Zend_Auth::getInstance()->getStorage()->write($userInfo); 
					} else {
						$this->_redirect('/');
						return;
					}
				} else {
					$_SESSION["registration_fb_profile"] = $user_profile;
					$this->_redirect('/?register=1');
					return;
				}
				
							
			} catch(FacebookApiException $e) {
				//die('Error, please contact an admin.');
				//in case we are no longer authenticated
				$this->_redirect('/auth/facebook');
				return;
			}
			
			if(!empty($_REQUEST['redirect'])){
				$this->_redirect($_REQUEST['redirect']);
                //$this->_redirect("http://www.google.com");
            }
			else{
                //$this->_redirect('/');
                if ($_COOKIE["history_url"] && $username == $_COOKIE["username"] ){
                    $this->_redirect($_COOKIE["history_url"] );
                }else{
                    $this->_redirect('/');  
                }
            }
			
		}
		
		$oathPermissions = array(
			'email',
			'offline_access',
			'photo_upload',
			'publish_stream',
			'publish_actions',
			'read_stream',
			'user_photos','user_status',
			'xmpp_login'
		);
		
		//2nd step of auth should come back fo this controller
		//while retaining our final redirect uri which can be relative.
		$redirectBase = 'http://'.$_SERVER['HTTP_HOST'].'/auth/facebook';
		if(!empty($_REQUEST['redirect']))
			$redirectBase .= '?redirect'.$_REQUEST['redirect'];
		
		$oauthUrl = $fb->getLoginUrl(array(
			'scope' => implode(',', $oathPermissions),
			'redirect_uri' => $redirectBase
		));
		
		$this->_redirect($oauthUrl);
	}
	
}
