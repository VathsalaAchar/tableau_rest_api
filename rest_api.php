<?php

class RESTAPI {
	protected $server;
	protected $site;
	protected $username;
	protected $password;
	protected $token;
	protected $site_id;
	protected $login_as_user_id;
	protected $last_error;
	protected $log_handle;
	protected $datasource_capabilities;
	protected $workbook_capabilities;
    
	/**
		Magic methods for object
	*/
	function __construct ($server, $username, $password, $site="",$login_as_user_id=null){
		$this->server = $server;
		$this->username = $username;
		$this->password = $password;
		$this->site = $site;
		$this->token = null;
		$this->site_id = null;
		$this->login_as_user_id = $login_as_user_id;
		$this->last_error = null;
		$this->log_handle = false;
		$this->datasource_capabilities = array ('ChangePermissions','Connect','Delete','ExportXml','Read','Write');
		$this->workbook_capabilities = array ('AddComment','ChangeHierarchy','ChangePermissions','Delete',
											'ExportData','ExportImage','ExportXml','Filter','Read','ShareView','ViewComments',
											'ViewUnderlyingData','WebAuthoring','Write');
		$this->site_roles = array('Interactor','Publisher','SiteAdministrator','Unlicensed','UnlicensedWithPublish','Viewer','ViewerWithPublish');
	}
   
	function __destruct(){
		if($this->log_handle !== false){
			fclose($this->log_handle);
		}
	}

	/**
		Logging functions
	*/
	public function enableLogging($filename){
		$logfile = fopen($filename,"w");
		if ($logfile == false){
			throw new Exception("Can't open $filename for logging");
		}
		$this->log_handle = $logfile;
		$this->log("\n------------------------------\n");
	}
	
	// write to log if logging enabled
	public function log($l){
		if($this->log_handle !== false){
			fwrite($this->log_handle,$l . "\n");
		}
	}
   
	/**
		Getter / Setters for object pieces
	*/
   
    public function getLastError(){
        $this->log($this->last_error);
        return $this->last_error;
    }
   
    protected function setLastError($e){
        $this->last_error = $e;
    }

	/**
		Login functions 
	*/
	protected function makeLoginPayload(){
		$payload = "<tsRequest><credentials name=\"{$this->username}\" password=\"{$this->password}\" ><site contentUrl=\"{$this->site}\" />";
		if($this->login_as_user_id !== null){
			$payload .= "<user id=\"{$this->login_as_user_id}\" />";
		}
		$payload .= "</credentials></tsRequest>";

		return $payload;
	}

	
	public function signin(){
		$payload = $this->makeLoginPayload();
        $url = $this->buildApiUrl("auth/signin",'login');
        $this->log($url);
        $api = new REST_XML_REQUEST($url);  
        $api->setXmlRequest($payload);
        $this->log($payload);
        $api->requestFromAPI();
        $xml = $api->getResponse();
        $this->token = $xml->credentials[0]['token'];
        $this->log($this->token);
        $this->site_id = $xml->credentials[0]->site[0]['id'];
        $this->log($this->site_id);
        unset($api); // Kill API call object
	}
	
	/*Utility function to build the URL string. Example:
		https://server/api/2.0/sites/abcd-123-6789/datasources
	*/
	protected function buildApiUrl($call, $login = false){

		//All calls but login and logout require the site
		if($login == 'login'){
			return $this->server . "/api/2.0/" . $call;
		}
		else{
			return $this->server . "/api/2.0/sites/{$this->site_id}/" .  $call;
		}
	}

	// URI is different from the actual URL you need to load a particular view from iframe or JS API
	public function convertViewContentUrlToEmbedUrl($contentUrl){
		//AdWordsAnalysis/sheets/AdwordsCreativeAnalysis 
		//views/workbook/sheet
		$url_split = explode("/",$contentUrl);
		return "views/" . $url_split[0] . "/" . $url_split[2];
	}
   
	/**
		Basic Querying / Get Methods
	*/
	
	// Baseline method for any request. Append method to base url
	public function queryResource($url_ending){
		$api_call = $this->buildApiUrl("$url_ending");
		$this->log($api_call);
		try{
			$api = new REST_XML_REQUEST($api_call,$this->token);  
            $api->requestFromAPI();
            $xml = $api->getResponse();
            return $xml;
		}
		catch (Exception $e){
            $this->log( $api->getLastError() );
			throw $e;
		}
	}
	
	public function queryDatasources(){
        return $this->queryResource("datasources"); 
	}
	
	// When querying by name, simplest to pull all datasources and slice via xpath query.
	// Nothing additional is returned by querying the datasource resource via UID
	public function queryDatasourceLUIDByName($name){
        $datasources = $this->queryDatasources();
        $datasource = $datasources->xpath("//t:datasource[@name='$name']");
        if( count($datasource) == 1){
            return $datasource[0]['id'];
        }
        else {
            throw new Exception("No datasource found with $name");
        }
	}
	
	public function queryDatasourceByLUID($luid){
        return $this->queryResource("datasources/$luid");
	}
	
	public function queryDatasourcePermissionsByLUID($luid){
        return $this->queryResource("datasources/$luid/permissions");
	}
	
	public function queryDatasourcePermissionsByName($name){
        $datasource = $this->queryDatasourceByName($name);
        $datasource_luid = $datasouce["id"];
        return $this->queryDatasourcePermissionsByLUID($datasource_luid);
	}
	
	public function queryGroups(){	
        return $this->queryResource("groups");
	}
	
	public function queryGroupLUIDByName($name){
        $groups = $this->queryGroups();
        $group = $groups->xpath("//t:group[@name='$name']");
        if ( count($group) == 1) {
            return $group[0]["id"];
        }
        else {
            throw new Exception("No group exists with name $name");
        }
	}
	
	public function queryProjects(){
        return $this->queryResource("projects");
	}
    
    public function queryProjectByLUID($luid){
        return $this->qureyResource("projects/$luid");
    }
	
	public function queryProjectPermissionsByLUID($luid){
        return $this->queryResource("projects/$luid/permissions");
	}
	
	public function queryProjectPermissionsByName($name){
        $projects = $this->queryProjects();
        $project = $projects->xpath("//t:project[@name='$name']");
        if( count($project) == 1 ){
            $project_luid = $project[0]["id"];
            return $this->queryProjectPermissionsByLUID($project_luid);
        }
        else{
            throw new Exception("No projects found named $name");
        }
	}
	
	public function querySites(){
        return $this->queryResource("sites/",'login');
	}
	
	public function querySiteByLUID($luid){
        return $this->queryResource("$luid");
	}
	
	public function querySiteByName($name){
        return $this->queryResource("$name" . "?key=name");
	}
	
	public function querySiteByContentUrl($content_url){
        return $this->queryResource("$content_url" . "?key=contentUrl");
	}
	
	public function queryUserByLUID($luid){
        return $this->queryResource("users/$luid");
	}
	
	public function queryUsers(){
        return $this->queryResource("users");
	}
	
	public function queryUserLUIDByUsername($username){
        $users = $this->queryUsers();
        //$this->log($users->asXML());
        $user = $users->xpath("//t:user[@name='$username']");
        if( count($user) == 1 ){
            $user_luid = $user[0]["id"];
            return $user_luid;
        }
        else{
            throw new Exception("No user found with name $username");
        }
	}
	
	public function queryUsersInGroupByLUID($luid){
        return $this->queryResource("groups/$luid/users");
	}
	
	public function queryUsersInGroupByName($group_name){
        $luid = $this->queryGroupLUIDByName($group_name);
        return $this->queryUsersInGroupByLUID($luid);
	}
	
	public function queryWorkbookByLUID($luid){
        return $this->queryResource("workbooks/$luid");
	}
	
	public function queryWorkbooksForUserByLUID($luid){
        return $this->queryResource("users/$luid/workbooks");
	}
	
	public function queryWorkbookForUsernameByWorkbookName($username,$wb_name){
        $workbooks =  $this->queryWorkbooksByUsername($username);
        $workbook = $workbooks->xpath("//t:workbook[@name='$wb_name']");
        if( count($workbook) == 1 ){
            $wb_luid = $workbook[0]["id"];
            return $this->queryWorkbookByLUID($wb_luid);
        }
        else{
            throw new Exception("No workbook by name '$name' found for username '$username'");
        }
	}
	
	// Workbooks are queried by user_uid, rather than by project, because they obey permissions
	public function queryWorkbooksByUsername($username){
        $user_luid = $this->queryUserLUIDByUsername($username);
        return $this->queryWorkbooksForUserByLUID($user_luid) ;
	}
	
	public function queryWorkbookPermissionsByLUID($luid){
        return $this->queryResource("workbooks/$luid/permissions");
	}
	
	public function queryWorkbookPermissionsForUsernameByWorkbookName($username,$wb_name){
        $wb_luid = $this->queryWorkbookForUsernameByWorkbookName($username,$wb_name);
        return $this->queryWorkbookPermissionsByLUID($wb_luid);
	}
   
	public function queryWorkbookConnectionsByLUID($luid){
        $this->queryResource("workbooks/$luid/connections");
	}
	
	public function queryWorkbookConnectionsForUsernameByWorkbookName($username,$wb_name){
        $wb_luid = $this->queryWorkbookForUsernameByWorkbookName($username,$wb_name) ;
        return $this->queryWorkbookConnectionsByLUID($wb_luid);
	}
	
   // UNFINSIHED 
   public function wildcardFilterWorkbooksByProjectName($project_name,$workbooks_xml){
       // $projects = $this->queryResource('projects');
       // $specific_project = $projects->xpath("//t:project[@name='$project_name']");
        //$project_id = $specific_project[0]["id"];
        $workbooks_in_project = $workbooks_xml->xpath("//t:project[contains(@name,'$project_name')]/..");   
        return $workbooks_in_project;
   }
   
  
   // Can be simplified, do some of this automatically
	public function saveWorkbookPreview($workbook_id,$workbook_url,$save_path){
		$full_save_location = $save_path . $workbook_url . ".png";
		$api_call = $this->buildApiUrl("workbooks/$workbook_id/previewImage");
        try{
			$api = new REST_XML_REQUEST($api_call,$this->token);
			$api->setResponseType('png');
			$response = $api->requestFromAPI();
			$png = $api->getResponse();
			if( file_exists($full_save_location) ){
			   // unlink($full_save_location);
			   // Skip if already exists
			   return;
			}
			$this->log("Saving thumbnail PNG to $full_save_location");
			$fp = fopen($full_save_location,'x');
			if($fp === false){
				throw new Exception("Could not open file for writing at $full_save_location");
			}
			fwrite($fp,$png);
			fclose($fp);
		}
		catch (Exception $e){
			fclose($fp);
			$this->log($e);
			throw $e;
		}
	}
   
   /**
		Add and create action methods. 
   */
    
	// Protected internal method to do an any add request. Returns response which is usually XML
	public function sendAddRequest($url,$request){
        $api = new REST_XML_REQUEST($url,$this->token);
        $api->setXmlRequest($add_request);
        $api->requestFromAPI();
        return $api->getResponse();
	}

	/**
		This is technically "Add User to Site" but you have to sign in to a site prior so 
		just called addUser
	*/	
   public function addUserByUsername($username,$site_role = 'Unlicensed'){
	   // Check to see if any role that is passed is a valid role
	   if(!in_array($site_role,$this->site_roles) ) { 
			throw new Exception("$site_role is not a valid siteRole in Tableau Server");
		}
		$add_request = "<tsRequest><user name=\"$username\" siteRole=\"$role\" /></tsRequest>";
		$this->log($add_request);
		$url = $this->buildApiUrl("users");
		$this->log($url);

        $new_user = $this->sendAddRequest($url,$add_request);
        return $new_user->user['id'];
   }

	/**
		This method allows you to create a new user and set their details. This requires both an Add and an Update REST call
	*/
	public function addUser($username,$fullname,$site_role = 'Unlicensed', $password = false, $email = false){
		// Add user_ID first, then update with full name
		$add_request = "<tsRequest><user name=\"$username\" siteRole=\"$site_role\" /></tsRequest>";
		$this->log($add_request);
		$url = $this->buildApiUrl("users");
		$this->log($url);
		try{
			$new_user_luid = $this->addUserByUsername($username,$site_role);
			try{
				return $this->updateUser($new_user_luid,$fullname,$password,$email);
			}
			catch(Exception $e) {
				$this->log("User $username was added with $new_user_luid but could not be updated with additional details");
				throw $e;
			}
		}
		catch(Exception $e){
			$this->log("User $username could not be added to the Server");
			throw $e;
		}
	}

	public function createGroup($group_name){
		$add_request = "<tsRequest><group name=\"$group_name\" /></tsRequest>";
		$this->log($add_request);
		$url = $this->buildApiUrl("groups");
		$this->log($url);
        $new_group = $this->sendAddRequest($url,$add_request);
        return $new_group->group['id'];

   }
   
	public function createProject($project_name,$project_desc = false){
		$add_request = "<tsRequest><project name='$project_name' ";
		if ($project_desc !== false){
		   $add_request .= "description='$project_desc'";
		}
		$add_request .= " /></tsRequest>";
		$this->log($add_request);
		$url = $this->buildApiUrl("projects");

        $new_project = $this->sendAddRequest($url,$add_request);
        return $new_project->project["id"];
	}
	
	// UNFINISHED
	public function createSite($site_name,$content_url,$admin_mode = 'ContentAndUsers',$num_users,$storage_quota_in_mb,$disable_subscriptions = 'false'){
		
	}
   
	public function addUserToGroupByLUID($user_luid,$group_luid){
		$add_request = "<tsRequest><user id=\"$user_luid\" /></tsRequest>";
		$url = $this->buildApiUrl("groups/$group_luid/users/");
        $this->sendAddRequest($url,$add_request);
	}
   
   /**
        To do an effective, successful add process you need to get the Group UID that matches the name
        You need both the Users UIDs for those who exist on the server, and also those who are in the Group currently
   */ 
	public function addUsersToGroup($users_array,$group_name){
		$group_luid = null;
		$current_site_users = array();
		$current_group_users = array();
		//Get all groups and their IDs from API
		if($this->log_handle !== false){
		   foreach($users_array as $user){
				$this->log("Syncing $user to $group_name");
		   }
		}    

        // Get users on site from API
        $group_luid = $this->getGroupLUIDByName($group_name);
        $users_q = $this->queryUsers();
        $users = $users_q->user;
        foreach($users as $user){
            $current_site_users[ (string) $user["name"] ] = (string) $user["id"];
        }
        $users_in_group = $this->queryResource("groups/$group_luid/users");
        
        // Get users already in the Group from API
        foreach($users_in_group as $user){
            $current_group_users [ (string) $user["name"] ] = (string) $user["id"]; 
        }
        // Generate array of new users to add
        $users_to_add = array();
        foreach($users_array as $user){
            if(!array_key_exists($user,$current_group_users) ){
                $users_to_add [ $user ] = $current_site_users[$user];
                $this->log("$user , {$current_site_users[$user]} will be added to $group_name");
            }   
            else{
                $this->log("$user, {$current_site_users[$user]} is already a member of $group_name");
            }
        }
              
        // Iterate through $users_array, sending add to group request for each
        $users_not_on_server = array();

        $users_added = 0;
        if(count($users_to_add) == 0) {
            $this->log("All users already are synced to $group_name");
            return $users_added;
        }
        
        foreach($users_to_add as $new_username => $new_user_luid){
            // Create errors list non-match, REST API errors, etc
            if(!array_key_exists($new_username, $current_site_users ) ){
                $users_not_on_server[] = $new_username;
                $this->log("$new_username does not exist on the current site");
            }
            else{
                $this->addUserToGroupByLUID($new_user_luid,$group_luid);
                $this->log("$new_username added successfully to $group_name");
                $users_added++;
            }
        }
        return $users_added;
   }
   
   /**
        Sync users assumes the array passed in has all of the usernames of users who belong in the group.
        Two passes: (1) Add any missing users (2) Remove any users who exist in Tableau Server Group but not in original array
   */
	public function syncUsersToGroup($users_array,$group_name){
		$group_luid = null;
		$current_group_users = array();
		$users_added = 0;
		$users_removed = 0;
		// First add all users that are missing
        $users_add = $this->addUsersToGroup($users_array,$group_name);
        // Then remove out any users who should not be in the group
   
        //Get all groups and their IDs from API
        if($this->log_handle !== false){
            foreach($users_array as $user){
                $this->log("Syncing $user to $group_name");
            }
        }
        $group_luid = $this->getGroupLUIDByName($group_name);

         
        // Get users already in the Group from API
        $users_in_group = $this->queryUsersInGroupByLUID($group_luid);
        foreach($users_in_group as $user){
           $current_group_users [ (string) $user["name"] ] = (string) $user["id"]; 
        }

        // Generate array of users to remove
        $users_to_remove = array();
        foreach($current_group_users as $user => $uid){
            if(!in_array($user, $users_array  ) ){
                $users_to_remove []= $user;
                $this->log("$user , $uid will be removed from $group_name");
            }   
            else{
                $this->log("$user, $uid is currently in and belongs in $group_name");
            }
        }
   
        // Remove the users in a batch process
        $users_removed = $this->removeUsersFromGroupByGroupName($users_to_remove,$group_name);
        $this->log("$users_added users added to $group_name\n$users_removed users removed from $group_name");
   }
   
   /**
		Remove / Delete Methods
   */
   
	// Generic internal method for any update request using the PUT verb
	public function sendUpdateRequest($url,$request){
        $api = new REST_XML_REQUEST($url,$this->token);
        $api->setXmlRequest($request);
        $api->setHttpVerb('put');
        $api->requestFromAPI();
        return $api->getResponse();
	}
   
	public function updateUser($user_luid,$full_name = false, $site_role = false, $password = false, $email = false){
		$update_request = "<tsRequest><user ";

		if( $username !== false){
			$update_request .= "fullName=\"$full_name\" ";
		}
		if( $site_role !== false){
			$update_request .= "siteRole=\"$site_role\" "; 
		}
		if( $email !== false){
			$update_request .= "email=\"$email\" ";
		}
		if( $password !== false){
			$update_request .= "password=\"$password\" ";
		}

		$update_request .= "/></tsRequest>";
		$url = $this->buildApiUrl("users/$user_luid");
		$this->log($url);

        return $this->sendUpdateRequest($url,$update_request);
	}

	public function updateWorkbookPermissionsByLUID($wb_luid,$xml_request){
		
	}

	// Returns a 1 so you can add if completes successfully
	public function sendDeleteRequest($url){
        $api = new REST_XML_REQUEST($url,$this->token);
        $api->setHttpVerb('delete');
        $api->requestFromAPI();
        $headers = $api->getLastResponseHeaders();
        if($headers['http_code'] === '204' ){
            $this->log("$user_luid removed successfully from $group_luid");
            return 1;
        }
        else{
            throw new Exception ("Request did not remove, instead had HTTP response: {$headers['http_code']}");
        }

	}
	
	public function removeUserFromGroupByLUID($user_luid,$group_luid){
		$url = $this->buildApiUrl("groups/$group_luid/users/$user_luid");
		$this->log("Removing via DELETE on $url");
        $this->sendDeleteRequest($url);
	}
	
	public function removeUsersFromGroupByGroupName($users_to_remove_array,$group_name){
        $group_luid = $this->getGroupLUIDByName($group_name);
        $users_removed = 0;
        if(count($users_to_remove_array) == 0) {
            $this->log("No users to remove from $group_name");
            return $users_removed;
        }
   
        // Get users already in the Group from API
        $users_in_group = $this->queryUsersInGroupByLUID($group_luid);
        foreach($users_in_group as $user){
            $current_group_users [ (string) $user["name"] ] = (string) $user["id"]; 
        }
   
        foreach($users_to_remove_array as $user){
            if( !array_key_exists($user,$current_group_users) ){
                $this->log("$user does not exist in $group_name");
            }
            else{
                $user_luid= $current_group_users [ $user ];
                $users_removed = $users_removed + $this->removeUserFromGroupByLUID($user_luid,$group_luid);

            }
        }
        return $users_removed;

	}
   
   // Must know the capability name and mode to delete it
   public function deleteWorkbookCapabilityForGroupByLUID($wb_luid,$group_luid,$capability_name,$capability_mode){
       $url = $this->buildApiUrl("workbooks/$wb_luid/permissions/groups/$group_luid/$capability_name/$capability_mode");
       $this->log("Deleting workbook capability via this URL: $url");
       $this->sendDeleteRequest($url);
    }
  
   /**
        Process to change a workbooks Permissions
        1) Get current Workbook permissions
        2) Delete any Permissions that you want to change. Must specify capability name and the mode it is set to
        3) Add Permissions back to workbook
   */
	public function setWorkbookPermissionsUsingGranteeCapabilities($workbook_luid,$caps_simplexml_obj){
        $workbook_permissions = $this->queryWorkbookPermissionsByLUID();

        // Array of arrays, [ID,capability name] (grab mode from the current capabilities at the last minute)
        $capabilities_to_remove  = array();

        $capabilities_xml = "";
        // Build each granteeCapabilities section, determine what needs to be removed
        foreach($caps_simplexml_obj as $group){
            $capabilities_xml .= "<granteeCapabilities> \n";
            $capabilities_xml .= $group->group->asXML() ;
            $capabilities_xml .= "\n<capabilities>\n";
            $group_luid = $group->group["id"];
            foreach($group->capabilities->capability as $cap){
                if( in_array( $cap["name"], $this->workbook_capabilities) ){
                    $capabilities_xml .= $cap->asXML() . "\n"  ;
                    $capabilities_to_remove[] = array($group_luid, $cap["name"] );
                };
            }
            $capabilities_xml .= "\n</capabilities></granteeCapabilities>";
        }
        // Remove all necessary capabilities
        foreach($capabilities_to_remove as $caps){
            $group_luid = $caps[0];
            $capability_name = $caps[1];
            $matching_group = $workbook_permissions->xpath("//t:group[@id='$group_id']/..");

            // Get all capabilities that match in name that fall under the group granted
            $matching_cap = $workbook_permissions->xpath("//t:granteeCapabilities[t:group[@id='$group_luid']]/ t:capabilities/t:capability[@name='$capability_name']");
            if( count($matching_cap) == 1){
                $capability_mode = $matching_cap[0]["mode"];
                $this->log("$group_luid, $capability_name : $capability_mode will be deleted");
                /*
                    Delete capability
                */
                $this->deleteWorkbookCapabilityForGroupUID($workbook_luid,$group_luid,$capability_name,$capability_mode);
            }
        }
   
        $request = "<tsRequest><permissions>";
        $request .= $capabilities_xml;
        $request .= "</permissions></tsRequest>";
        
        $this->log($request);
        $api_call = $this->buildApiUrl("workbooks/$workbook_id/permissions");
        $this->sendUpdateRequest($api_call,$request);
   }  
}

/**
  Class to handle REST Requests that result in XML responses  
  If no token, assumed to be login or logout request
  Else must pass token from previous login
*/
class REST_XML_REQUEST {
    protected $base_url;
    protected $xml_request;
    protected $http_verb;
    protected $token;
    protected $response_type;
    protected $defined_response_types;
    protected $defined_http_verbs;
    protected $raw_response;
    protected $last_error;
    protected $simple_xml_object;
    protected $last_url_request;
    protected $last_response_headers;
    
    function __construct($url,$token = false){
        $this->defined_response_types = array('xml','png');
        $this->defined_http_verbs = array('post','get','put','delete');
        
        $this->base_url = $url;
        $this->xml_request = null;
        $this->token = $token;
        $this->raw_response = null;
        $this->last_error = null;
        $this->last_url_request = null;
        $this->last_response_headers = null;
        $this->simple_xml_object = null;
        
        $this->setHttpVerb('post');
        $this->setResponseType('xml');
    }
    
    // Probably should validate the XML here
    public function setXmlRequest($xml){
        $this->xml_request = $xml;
        return true;
    }
    
    public function setResponseType($response_type){
        $response_type = strtolower($response_type);
        if(in_array($response_type,$this->defined_response_types)){
            $this->response_type = $response_type;
            return true;
        }
        else{
            throw new Exception("$response_type is not defined as a valid response type in this library");
        }
    }
    
    public function setHttpVerb($verb){
        $verb = strtolower($verb);
        if(in_array($verb,$this->defined_http_verbs)){
            $this->http_verb = $verb;
            return true;
        }
        else {
			throw new Exception("$verb is not defined as a valid HTTP verb in this library");
        }
        
    }
    
    public function getRawResponse(){
        return $this->raw_response;
    }
    
    public function getLastError(){
        return $this->last_error;
    }
    
    public function getLastUrlRequest(){
        return $this->last_url_request;
    }
    
    public function getLastResponseHeaders(){
        return $this->last_response_headers;
    }
    
    /**
      public getter method for the call's response, if XML, register the Tableau XPath namespace as 't' for later querying
    */
    public function getResponse(){
        if($this->response_type == 'xml' && $this->simple_xml_object !== null){
           //echo htmlspecialchars($response);        
           // Register a namespace for xpath queries (oi)
           $this->simple_xml_object->registerXPathNamespace('t', 'http://tableausoftware.com/api');
           return $this->simple_xml_object;
        }
        else {
           return $this->raw_response;
        }
    }

	/**
		Internal method that does the bulk of the HTTP request. Uses PHP CURL rather than pecl http library
	*/
    protected function _make_request($page_number = 1){
        $url = $this->base_url;
		$url .= "?pageNumber=$page_number";
        $this->last_url_request = $url;
        $req = curl_init($url);
		if($req === false){
			throw new Exception("Error with setting URL in cURL library");
		}
       
       // Set to a GET if no data to POST
       
       if($this->http_verb == 'delete'){
           curl_setopt($req, CURLOPT_POST,0);
           curl_setopt($req, CURLOPT_CUSTOMREQUEST,"DELETE");
       }
       // Get when no XML_request
       elseif($this->xml_request == null){
            curl_setopt($req, CURLOPT_HTTPGET,true);
       }
       elseif ($this->http_verb == 'post'){
            curl_setopt($req, CURLOPT_POST,1);
            curl_setopt($req, CURLOPT_POSTFIELDS, utf8_encode($this->xml_request) );
       }
       elseif ($this->http_verb == 'put'){
           curl_setopt($req, CURLOPT_POST,0);
           curl_setopt($req, CURLOPT_CUSTOMREQUEST,"PUT");
           curl_setopt($req, CURLOPT_POSTFIELDS, utf8_encode($this->xml_request) );
       }

       // All calls other than signin or signout have to pass the header with the token
       if($this->token != false){
            curl_setopt($req, CURLOPT_HTTPHEADER, array("X-tableau-auth: {$this->token}") );
       }
       
       if($this->response_type == 'png'){
           curl_setopt($req, CURLOPT_BINARYTRANSFER,1);
       }
       
		curl_setopt($req, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($req, CURLOPT_CONNECTTIMEOUT,60); // Increase connect time limit
		curl_setopt($req, CURLOPT_TIMEOUT,60); // Increase response time limit

		$response = curl_exec($req);
		if($response === false){
			$error = curl_error($req);
			throw new Exception("cURL HTTP request failed: $error");
		}
		$curlinfo = curl_getinfo($req);
       
		$this->last_response_headers = $curlinfo;
		$this->raw_response = $response;
       
		// Check for HTTP Response codes
		$http_response = $curlinfo['http_code'];
		if ($http_response >= (int) 400){
		   $this->last_error = $this->raw_response;
		   throw new Exception("HTTP Response code $http_response is an error code. Retrieve full error for more details");
		}
    }
    
	/**
		Method to use to make request after all setter methods have been called
	*/
	public function requestFromAPI(){
        $this->_make_request();
       // Paginate through any XML response to bring it all back, if necessary
       if ($this->response_type == 'xml'){
           // DELETE request might respond with nothing
           if($this->raw_response == "") { return true; }
           $xml = simplexml_load_string( utf8_decode( $this->raw_response ) );
                     
           // Paginate on larger requests
           if($xml->pagination["pageNumber"] !== null){
               $page_number = (int) $xml->pagination["pageNumber"];    
               $page_size = (int) $xml->pagination["pageSize"];
               $total_available = (int) $xml->pagination['totalAvailable'];
               $total_pages = ceil($total_available / $page_size) ;

               $combined_xml_string = '<tsResponse xmlns="http://tableausoftware.com/api" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://tableausoftware.com/api http://tableausoftware.com/api/ts-api-2.0.xsd">';
               foreach($xml as $first_obj){
                  if( $first_obj->getName() !== 'pagination'){
                     $full_xml_obj = $first_obj;
                  }
            
               }
              
               // Convert the internal part of the XML response that is not Pagination back into XML text
               // Then put it back a new XML object
               $new_xml = simplexml_load_string ( $full_xml_obj->asXML() );
              
               foreach($full_xml_obj as $a){
                   $combined_xml_string .= $a->asXML();
               }
                
               if($total_pages > 1){
                for($i=2;$i <= $total_pages; $i++){
                    $response = $this->_make_request($i); // Get next page
                    if($response === false){
                        return false;
                    }
                    else{
                        $xml = simplexml_load_string( utf8_decode( $this->raw_response ) );
                        foreach($xml as $first_obj){
                          if( $first_obj->getName() !== 'pagination'){
                             foreach($first_obj->children() as $a){
                                $combined_xml_string .= $a->asXML();
                             }
                          }
                        }
                    }
                }
               }
               $combined_xml_string .= "</tsResponse>";
               
               $this->simple_xml_object = simplexml_load_string ( $combined_xml_string );

           }
           else{
               $this->simple_xml_object = simplexml_load_string( utf8_decode( $this->raw_response ) );
           }
       }
        else return true;          
    }
}

function get_trusted_ticket($host,$username,$site){
    //$host = 'http://127.0.0.1/trusted';
    
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL,"$host" . "/trusted");
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_HEADER,0);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: application/x-www-form-urlencoded;charset=UTF-8") );
    //curl_setopt($ch, CURLOPT_POSTFIELDS,
   //             "postvar1=value1&postvar2=value2&postvar3=value3");

    // in real life you should use something like:
     curl_setopt($ch, CURLOPT_POSTFIELDS, 
              http_build_query(array('username' => $username, 'target_site' => $site)));

    // receive server response ...
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_VERBOSE,1);

    $server_output = curl_exec ($ch);

    curl_close ($ch);
    //echo $server_output;
    return $server_output;
}

?>