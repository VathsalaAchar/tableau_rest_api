
try:
    # Python 3.x
    from urllib.request import urlopen, request
except:
    # Python 2.x
    import urllib2

# For parsing XML responses

try:
    from lxml import etree
except ImportError:
    import xml.etree.ElementTree as etree

# StringIO helps with lxml UTF8 parsing

from StringIO import StringIO
import math
    
class RESTAPI:

    '''Defines a class that represents a RESTful connection to Tableau Server.'''
    def __init__(self, server, username, password, site=""):
        self.__server = server
        self.__site = site
        self.__username = username
        self.__password = password
        self.__token = None # Holds the login token from the Sign In call
        self.__site_id = ""
        self.__login_as_user_id = None
        self.__last_error = None
        self.__log_handle = None
        self.__tableau_namespace = 'http://tableausoftware.com/api'
        self.__datasource_capabilities = ('ChangePermissions','Connect','Delete','ExportXml','Read','Write')
        self.__workbook_capabilities = ('AddComment','ChangeHierarchy','ChangePermissions','Delete','ExportData','ExportImage','ExportXml','Filter','Read','ShareView','ViewComments','ViewUnderlyingData','WebAuthoring','Write')
        self.__site_roles = ('Interactor','Publisher','SiteAdministrator','Unlicensed','UnlicensedWithPublish','Viewer','ViewerWithPublish')
        self.__ns_map = { 't' : 'http://tableausoftware.com/api'}
    
    def enable_logging(self, filename):
        lh = open(filename, 'w') 
        self.__log_handle = lh
            
        
    def log(self, l):
        if self.__log_handle != None:
            self.__log_handle.write(l + '\n')
        
    def get_last_error(self):
        self.log(self.__last_error)
        return self.__last_error
        
    def set_last_error(self, error):
        self.__last_error = error

    def __make_login_payload(self):
        '''Generates the XML payload for the Sign In call.
           Pass the username and password of an administrator
           user.
        '''
        _payload = """<tsRequest><credentials name="%s" password="%s" ><site contentUrl="%s" /></credentials></tsRequest>"""
        return _payload % (self.__username, self.__password, self.__site)

    def build_api_url(self, call, login = False):
        if login == 'login':
            return self.__server + "/api/2.0/" + call
        else:
            return self.__server + "/api/2.0/sites/" + self.__site_id + "/" + call

    def signin(self):
        payload = self.__make_login_payload()
        url = self.build_api_url("auth/signin",'login')
        self.log(url)
        api = REST_XML_REQUEST(url)
        api.set_xml_request(payload)
        self.log(payload)
        api.request_from_api()
        self.log(api.get_raw_response())
        xml = api.get_response();
        credentials_element = xml.xpath('//t:credentials',namespaces=self.__ns_map)
        self.__token = credentials_element[0].get("token")
        self.log("Token is " + self.__token)
        self.__site_id = credentials_element[0].xpath("//t:site", namespaces=self.__ns_map)[0].get("id")
        self.log("Site ID is " + self.__site_id)
    
    def signout(self):
        url = self.build_api_url("auth/signout","login")
        self.log(url)
        api = REST_XML_REQUEST(url)
        api.set_xml_verb('post')
        api.request_from_api()
        self.log('Signed out successfully')
  
    # URI is different form actual URL you need to load a particular view in iframe
    def convert_view_content_url_to_embed_url(self,content_url):
        split_url = content_url.split('/')
        return 'views/' + split_url[0] + "/" + split_url[2]
    
    ##
    ## Basic Querying / Get Methods
    ##
    
    # baseline method for any get request. appends to base url
    def query_resource(self, url_ending):
        api_call = self.build_api_url(url_ending)
        try:
            api = REST_XML_REQUEST(api_call,self.__token)
            api.request_from_api()
            xml = api.get_response().getroot() # return Element rather than ElementTree
            return xml
        except Exception as e:
            self.log(e[0])
    
    def query_datasources(self):
        return self.query_resource("datasources")
    
    def query_datasource_luid_by_name(self,name):
        datasources = self.query_datasources()
        datasource = datasources.xpath('//t:datasource[@name="{}"]'.format(name),namespaces=self.__ns_map)
        if len(datasource) == 1:
            return datasource[0].get("id")
        else:
            raise NoMatchFoundException("No datasource found with name " + name)

    def query_datasource_by_luid(self,luid):
        return self.query_resource('datasources/{}'.format(luid) )
    
    def query_datasource_permissions_by_luid(self,luid):
        return self.query_resource( 'datasources/{}/permissions'.format(luid) )

    
    def query_datasource_permissions_by_name(self,name):
        datasource = self.query_datasource_by_name(name)
        datasource_luid = datasource.get('id')
        return self.query_datasource_permissions_by_luid(datasource_luid)

    
    def query_groups(self):
        return self.query_resource("groups")
    
    def query_group_luid_by_name(self,name): 
        groups = self.query_groups()
        group = groups.xpath('//t:group[@name="{}"]'.format(name),namespaces=self.__ns_map)
        if len(group) == 1:
            return group[0].get("id")
        else:
            raise NoMatchFoundException("No group found with name " + name)

    
    def query_projects(self):
        return self.query_resource("projects")
    
    def query_project_by_luid(self,luid):
        return self.query_resource( "projects/{}".format(luid) )


    def query_project_permissions_by_luid(self,luid):
        return self.query_resource( "projects/{}/permissions".format(luid) )
            
#    def query_project_permissions_by_name(self,name):

    # Site queries don't have the site portion of the URL, so login option gets correct format
    def query_sites(self):
        return self.query_resource("sites/",'login')

            
    def query_site_by_luid(self,luid):
        return self.query_resource(luid)

    def query_site_by_name(self,name):
        return self.query_resource(name + "?key=name")
    
    def query_site_by_content_url(self,content_url):
        return self.query_resource(content_url + "?key=contentUrl")
            
    def query_users_by_luid(self,luid):
        return self.query_resource( "users/{}".format(luid) )
    
    def query_users(self):
        return self.query_resource("users")
            
    def query_user_luid_by_username(self,username):
        users = self.query_users()
        user = users.xpath('//t:user[@name="{}"]'.format(username),namespaces=self.__ns_map)
        if len(user) == 1:
            return user[0].get("id")
        else:
            raise NoMatchFoundException("No user found with username " + username)
    
    def query_users_in_group_by_luid(self,luid):
        return self.query_resource( "groups/{}/users".format(luid) )
            
    def query_users_in_group_by_name(self,group_name):
        luid = self.query_group_luid_by_name(group_name)
        return self.query_users_in_group_by_luid(luid)

    def query_workbook_by_luid(self,luid):
        return self.query_resource( "workbooks/{}".format(luid) )

    def query_workbooks_for_user_by_luid(self,luid):
        return self.query_resource("users/{}/workbooks".format(luid) )

            
    def query_workbook_for_username_by_workbook_name(self,username,wb_name):
        workbooks = self.query_workbooks_by_username(username)
        workbook = workbooks.xpath('//t:workbook[@name="{}"]'.format(wb_name),namespaces=self.__ns_map)
        if len(workbook) == 1:
            wb_luid = workbook[0].get("id")
            return self.query_workbook_by_luid(wb_luid)
        else:
            raise NoMatchFoundException("No workbook found for username " + username + " named " + wb_name)

    
    def query_workbooks_by_username(self,username):
        user_luid = self.query_user_luid_by_username(username)
        return self.query_workbooks_for_user_by_luid(user_luid)
    
    def query_workbook_permissions_for_username_by_workbook_name(self,username,wb_name):
        wb_luid = self.query_workbook_for_username_by_workbook_name(username,wb_name)
        return self.query_workbook_permissions_by_luid(wb_luid)
            
    # Need to figure how to use this to update the connections in a workbook. Seems to return
    # LUIDs for connections and the datatypes, but no way to distinguish them
    # Ask Tyler Doyle?
    def query_workbook_connections_for_username_by_workbook_name(self,username,wb_name):
        wb_luid = self.query_workbook_for_username_by_workbook_name(username,wb_name)
        return self.query_workbook_connections_by_luid(wb_luid)
    
    def send_add_request(self,url,request):
        api = REST_XML_REQUEST(url,self.__token)
        api.set_xml_request(request)
        api.request_from_api()
        xml = api.get_response().getroot() # return Element rather than ElementTree
        return xml
        
    def add_user_by_username(self,username, site_role = 'Unlicensed'):
        # Check to make sure role that is passed is a valid role in the API
        try:
            self.__site_roles.index(site_role)
        except: 
            raise Exception(site_role + " is not a valid site role in Tableau Server")
        # See if username already exists, if so, don't do anything
        try: 
            username_luid = self.query_user_luid_by_username(username)
            self.log("Username " + username + " already exists on the server as " + username_luid)
            raise AlreadyExistsException("Username " + username + " already exists on the server as " + username_luid, username_luid)
        # If there is no match, add the user
        except NoMatchFoundException:
            self.log("Adding " + username)
            add_request = '<tsRequest><user name="{}" siteRole="{}" /></tsRequest>'.format(username,site_role)
            self.log(add_request)
            url = self.build_api_url('users')
            self.log(url)
            new_user = self.send_add_request(url,add_request)
            new_user_luid = new_user.xpath('//t:user',namespaces=self.__ns_map)[0].get("id")
            return new_user_luid
        except:
            raise

    # This is "Add User to Site"
    def add_user(self,username,fullname,site_role = 'Unlicensed', password = False, email = False):
        # Add username first, then update with full name
        add_request = '<tsRequest><user name="{}" siteRole="{}" /></tsRequest>'.format(username,site_role)
        self.log(add_request)
        url = self.build_api_url('users')
        self.log(url)
        try:
            new_user_luid = self.add_user_by_username
            return self.update_user(new_user_luid,fullname,password,email)
        except AlreadyExistsException as e:
            self.log("Username " + username + " already exists on the server with luid " + e.existing_luid)
            return e.existing_luid
           # return self.update_user(new_user_luid,fullname,password,email)

           
    def create_group(self,group_name):
        add_request = '<tsRequest><group name="{}" /></tsRequest>'.format(group_name)
        self.log(add_request)
        url = self.build_api_url("groups")
        self.log(url)
        new_group = send_add_request(url,add_request)
        return new_group.xpath('//t:group',namespaces=self.__ns_map)[0].get("id")
        
    def create_project(self,project_name, project_desc = False):
        add_request = '<tsRequest><project name="${}" '.format(project_name)
        if project_desc != False:
            add_request = add_request + 'description="{}"'.format(project_desc)
        add_request = add_request + " /></tsRequest>"
        self.log(add_request)
        url = self.build_api_url("projects")
        new_project = self.send_add_request(url,add_request)
        return new_project.xpath('//t:project',namespaces=self.__ns_map)[0].get("id")
    
    def add_user_to_group_by_luid(self,user_luid,group_luid):
        add_request = '<tsRequest><user id="{}" /></tsRequest>'.format(user_luid)
        url = self.build_api_url("groups/{}/users/".format(group_luid))
        self.send_add_request(url,add_request)
        
    ### Update Methods
    def send_update_request(self,url,request):
        api = REST_XML_REQUEST(url,self.__token)
        api.set_xml_request(request)
        api.set_http_verb('put')
        api.request_from_api()
        return api.get_response()
        
    def update_user(self,user_luid, full_name = False,site_role = False, password = False, email = False):
        # Check if user_luid exists
        self.query_user_by_luid(user_luid)
        update_request = "<tsRequest><user "
        if full_name != False:
            update_request = update_request + 'fullName="{}" '.format(full_name)
        if site_role != False:
            update_request = update_request + 'siteRole="{}" '.format(site_role)
        if email != False:
            update_request = update_request + 'email="{}" '.format(email)
        if password != False:
            update_request = update_request + 'password="{}" '.format(password)
        update_request = update_request + "/></tsRequest>"
        url = self.build_api_url("users/{}".format(user_luid) )
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url,update_request)
    
    def update_datasource_by_luid(self,datasource_luid,new_datasource_name = False, new_project_luid = False, new_owner_luid = False):
        # Check if datasource_luid exists
        self.query_datasource_by_luid(datasource_luid)
        update_request = "<tsRequest><datasource"
        if new_datasource_name != False:
            update_request = update_request + ' name="{}" '.format(new_datasource_name)
        update_request = update_request + ">" # Complete the tag no matter what
        if new_project_luid != False:
            update_request = update_request + '<project id="{}"/>'.format(new_project_luid)
        if new_owner_luid != False:
            update_request = update_request + '<owner id="{}"/>'.format(new_owner_luid)
        update_requeest = update_request + "</datasource></tsRequest?"
        url = self.build_api_url("datasources/{}".format(datasource_luid))
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url,update_request)
    
    def __build_connection_update_xml(self,new_server_address = False, new_server_port = False, new_connection_username = False, new_connection_password = False):
        update_request = "<tsRequest><connection "
        if new_server_address != False:
            update_request = update_request + 'serverAddress="{}" '.format(new_server_address)
        if new_server_port != False:
            update_request = update_request + 'serverPort="{}" '.format(new_server_port)
        if new_connection_username != False:
            update_request = update_request + 'userName="{}" '.format(new_connection_username)
        if new_connection_username != False:
            update_request = update_request + 'password="{}"'.format(new_connection_password)
        update_request = update_request + "/></tsRequest>"
        return update_request
        
    def update_datasource_connection_by_luid(self,datasource_luid, new_server_address = False, new_server_port = False, new_connection_username = False, new_connection_password = False):
        # Check if datasource_luid exists
        self.query_datasource_by_luid(datasource_luid)
        update_request = self.__build_connection_update_xml(new_server_address,new_server_port,new_connection_username,new_connection_password)
        url = self.build_api_url("datasources/{}/connection".format(datasource_luid))
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url,update_request)
        
    def update_group_by_luid(self,group_luid,new_group_name):
        # Check that group_luid exists
        self.query_group_by_luid(group_luid)
        update_request = '<tsRequest><group name="{}" /></tsRequest>'.format(new_group_name)
        url = self.build_api_url("groups/{}").format(grouP_luid))
        self.log(update_request)
        self.log(url)
        return send_update_request(url,update_request)
    
    def update_project_by_luid(self,project_luid,new_project_name = False, new_project_description = False):
        # Check that project_luid exists
        self.query_project_by_luid(project_luid)
        update_request = '<tsRequest><project '
        if new_project_name != False:
            update_request = update_request + 'name="{}" '.format(new_project_name)
        if new_project_description != False:
            update_request = update_request + 'description="{}"'.format(new_project_description)
        update_request = update_request + "/><tsRequest>"
        self.log(update_request)
        self.log(url)
        return send_update_request(url,update_request)
    
    #Update site has a ton of options
    #def update_site_by_luid(self,
    
    # Docs do not list a name update function. Is that true?
    def update_workbook_by_luid(self,workbook_luid,new_project_luid = False,new_owner_luid = False):
        # Check that workbook exists
        self.query_workbook_by_luid(workbook_luid)
        update_request = "<tsRequest><workbook>"
        if new_project_luid != False:
            # Check if new project_luid exists with query
            self.query_project_by_luid(new_project_luid)
            update_request = update_request + '<project id="{}" />'.format(new_project_luid)
        if new_owner_luid != False:
            # Check if new owner_luid exists
            self.query_user_by_luid(new_owner_luid)
            update_request = update_request + '<owner id="{}" />'.format(new_owner_luid)
        update_request = update_request + '</workbook></tsRequest>'
        self.log(update_request)
        seld.log(url)
        return send_update_request(url,update_request)
        
    # To do this, you need the workbook's connection_luid. Seems to only come from "Query Workbook Connections", which does
    # not return any names, just types and LUIDs
    def update_workbook_connection_by_luid(self,wb_luid,connection_luid, new_server_address = False, new_server_port = False, new_connection_username = False, new_connection_password = False):
        # Check if datasource_luid exists
        self.query_workbook_by_luid(wb_luid)
        self.query_workbook_connection
        update_request = self.__build_connection_update_xml(new_server_address,new_server_port,new_connection_username,new_connection_password)
        url = self.build_api_url("workbooks/{}/connections/{}".format(wb_luid,connection_luid))
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url,update_request)   
        
    ### Figure out how response comes via http2lib, handle appropriately
    def send_delete_request(self,url):
        api = REST_XML_REQUEST(url,self.__token)
        api.set_http_verb('delete')
        api.request_from_api()
        headers = api.get_last_response_headers()
        #if headers['http
    
    def delete_datasource_by_luid(self,datasource_luid):
        # Check if datasource_luid exists
        self.query_datasource_by_luid(datasource_luid)
        url = this.build_api_url("datasources/{}".format(datasource_luid))
        self.log("Deleting datasource via  " + url)
        self.send_delete_request(url)
        
    def delete_project_by_luid(self,project_luid):
        # Check if project_luid exists
        self.query_project_by_luid(project_luid)
        url = this.build_api_url("projects/{}".format(project_luid))
        self.log("Deleting project via  " + url)
        self.send_delete_request(url)
        
    def delete_site_by_luid(self):
        url = this.build_api_url("/{}".format(self.__site_luid) )
        self.log("Deleting site via " + url)
        self.send_delete_request(url)
    
    def delete_workbook_by_luid(self,wb_luid):
        # Check if workbook_luid exists
        self.query_workbook_by_luid(wb_luid)
        url = this.build_api_url("workbooks/{}".format(wb_luid))
        self.log("Deleting workbook via " + url)
        self.send_delete_request(url)
    
    def delete_workbook_from_user_favorites_by_luid(self,wb_luid,user_luid):
        # Check if user and workbook exist
        self.query_workbook_by_luid(wb_luid)
        self.query_user_by_luid(user_luid)
        url = this.build_api_url("favorites/{}/workbooks/{}".format(user_luid,wb_luid))
        self.log("Removing workbook from favorites via " + url)
        self.send_delete_erequest(url)
    
    def remove_user_from_group_by_luid(self,user_luid,group_luid):
        # Check if user and group luids exist
        self.query_user_by_luid(user_luid)
        self.query_group_by_luid(group_luid)
        url = this.build_api_url("groups/{}/users/{}".format(user_luid,group_luid))
        self.log("Removing user from group via DELETE on " + url)
        self.send_delete_request(url)
    
    def remove_user_from_site_by_luid(self,user_luid):
        # Check if user_luid exists
        self.query_user_by_luid(user_luid)
        url = this.build_api_url("users/{}".format(user_luid))
        self.log("Removing user from site via DELETE on " + url)
        self.send_delete_request(url)
    
    ### Permissions delete -- this is "Delete Workbook Permissions" for users or groups
    def delete_workbook_capability_for_user_by_luid(self,wb_luid,user_luid,capability_name,capability_mode):
        url = self.build_api_url("workbooks/{}/permissions/users/{}/{}/{}".format(wb_luid,user_luid,capability_name,capability_mode))
        self.log("Deleting workbook capability via this URL: " + url)
        self.__send_delete_request(url)
        
    def delete_workbook_capability_for_group_by_luid(self,wb_luid,group_luid,capability_name,capability_mode):
        url = self.build_api_url("workbooks/{}/permissions/groups/{}/{}/{}".format(wb_luid,group_luid,capability_name,capability_mode))
        self.log("Deleting workbook capability via this URL: " + url)
        self.__send_delete_request(url)
        
    ### Publish methods -- workbook, datasources, file upload
        
# Handles all of the actual HTTP calling
class REST_XML_REQUEST:
    def __init__ (self, url, token = False):
        self.__defined_response_types = ('xml','png')
        self.__defined_http_verbs = ('post','get','put','delete')
        self.__base_url = url
        self.__xml_request = None
        self.__token = token
        self.__raw_response = None
        self.__last_error = None
        self.__last_url_request = None
        self.__last_response_headers = None
        self.__xml_object = None
        self.__ns_map = { 't' : 'http://tableausoftware.com/api'}
        try:
            self.set_http_verb('post')
            self.set_response_type('xml')
        except:
            raise
    
    def set_xml_request(self,xml_request):
        self.__xml_request = xml_request
        return True
    
    def set_http_verb(self,verb):
        verb = verb.lower()
        if verb in self.__defined_http_verbs:
            self.__http_verb = verb
        else:
            raise Exception('HTTP Verb ' + verb + ' is not defined for this library')
    
    def set_response_type(self,response_type):
        response_type = response_type.lower()
        if response_type in self.__defined_response_types:
            self.__response_type = response_type
        else:
            raise Exception('Response type ' + response_type + ' is not defined in this library')
            
    def get_raw_response(self):
        return self.__raw_response

    def get_last_error(self):
        return self.__last_error
    
    def get_last_url_request(self):
        return self.__last_url_request
    
    def get_last_response_headers(self):
        return self.__last_response_headers
        
    def get_response(self):
        if self.__response_type == 'xml' and self.__xml_object != None:
            return self.__xml_object
        else:
            return self.__raw_response
            
    # Internal method to handle all of the http request variations, using given library.
    # Using urllib2 with some modification, you could substitute in Requests or httplib
    # depending on preference. Must be able to do the verbs listed in self.defined_http_verbs
    # Larger requests require pagination (starting at 1), thus page_number argument can be called.
    def __make_request(self, page_number = 1):
        url = self.__base_url + "?pageNumber=%s"
        url = url % (page_number)
        self.__last_url_request = url
        
        # Logic to create correct request
        opener = urllib2.build_opener(urllib2.HTTPHandler)
        request = urllib2.Request(url)
        if self.__http_verb == 'delete':
            request.get_method = lambda: 'DELETE'
        if self.__xml_request != None:
            if self.__http_verb == 'put'  or 'post':
                request.add_data( self.__xml_request.encode("utf8") )
        if self.__http_verb == 'put':
            request.get_method = lambda: 'PUT'
        if self.__token != False:
            request.add_header('X-tableau-auth', self.__token)
        
        #Need to handle binary return for image somehow
        try:
            response = opener.open(request)
            self.__raw_response = response.read() # Leave the UTF8 decoding to lxml
        except: 
            raise
    
    def request_from_api(self):
        try:
            self.__make_request()
        except:
            raise
        if self.__response_type == 'xml':
            if self.__raw_response == '':
                return True
            utf8_parser = etree.XMLParser(encoding='utf-8')
            xml = etree.parse(StringIO(self.__raw_response), parser=utf8_parser)
            # Set the XML object to the first returned. Will be replaced if there is pagination
            self.__xml_object = xml 
            for pagination in xml.xpath('//t:pagination',namespaces=self.__ns_map):

                page_number = int(pagination.get('pageNumber'))
                page_size = int(pagination.get('pageSize'))
                total_available = int(pagination.get('totalAvailable'))
                total_pages = int(math.ceil( float(total_available) / float(page_size)))
                combined_xml_string = '<tsResponse xmlns="http://tableausoftware.com/api" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://tableausoftware.com/api http://tableausoftware.com/api/ts-api-2.0.xsd">'
                
                for obj in xml.getroot():
                    if obj.tag != 'pagination':
                        full_xml_obj = obj
                
                # Convert the internal part of the XML response that is not Pagination back into xml text
                # Then convert innermost part into a new XML object
                new_xml_text_lines = etree.tostring(full_xml_obj).split("\n")
                # First and last tags should be removed (spit back with namespace tags that will be included via start text
                a = new_xml_text_lines[1:]
                xml_text_lines = a[:-2]     

                if total_pages > 1:
                    for i in xrange(2,total_pages+1):

                        response = self.__make_request(i) # Get next page
                        xml = etree.parse(StringIO(self.__raw_response), parser=utf8_parser)
                        for obj in xml.getroot():
                            if obj.tag != 'pagination':
                                full_xml_obj = obj
                        new_xml_text_lines = etree.tostring(full_xml_obj).split("\n")
                        a = new_xml_text_lines[1:] #Chop first tag
                        xml_text_lines.extend(a[:-2]) # Add the newly brought in lines to the overall text lines
                        
                for line in xml_text_lines:
                    combined_xml_string = combined_xml_string + line
                combined_xml_string = combined_xml_string + "</tsResponse>";

                self.__xml_object = etree.parse(StringIO(combined_xml_string), parser=utf8_parser)           

class NoMatchFoundException(Exception):
    def __init__ (self,msg):
        self.msg = msg

class AlreadyExistsException(Exception):
    def __init__ (self,msg,existing_luid):
        self.msg = msg
        self.existing_luid = existing_luid