try:
    # Python 3.x
    from urllib.request import urlopen, request
except:
    # Python 2.x
    import urllib, urllib2

# For parsing XML responses

try:
    from lxml import etree
except ImportError:
    import xml.etree.ElementTree as etree

# StringIO helps with lxml UTF8 parsing

from StringIO import StringIO
import math, time, random, os


class TabRestApi:
    # Defines a class that represents a RESTful connection to Tableau Server.
    def __init__(self, server, username, password, site_content_url=""):
        self.__server = server
        self.__site = site_content_url
        self.__username = username
        self.__password = password
        self.__token = None  # Holds the login token from the Sign In call
        self.__site_luid = ""
        self.__login_as_user_id = None
        self.__last_error = None
        self.__logger = None
        self.__tableau_namespace = 'http://tableausoftware.com/api'
        self.__datasource_capabilities = ('ChangePermissions', 'Connect', 'Delete', 'ExportXml', 'Read', 'Write')
        self.__workbook_capabilities = (
            'AddComment', 'ChangeHierarchy', 'ChangePermissions', 'Delete', 'ExportData', 'ExportImage', 'ExportXml',
            'Filter', 'Read', 'ShareView', 'ViewComments', 'ViewUnderlyingData', 'WebAuthoring', 'Write')
        self.__site_roles = (
            'Interactor', 'Publisher', 'SiteAdministrator', 'Unlicensed', 'UnlicensedWithPublish', 'Viewer',
            'ViewerWithPublish')
        self.__ns_map = {'t': 'http://tableausoftware.com/api'}
        self.__server_to_rest_capability_map = {'Add Comment': 'AddComment',
                                                'Move': 'ChangeHierarchy',
                                                'Set Permissions': 'ChangePermissions',
                                                'Connect': 'Connect',
                                                'Delete': 'Delete',
                                                'View Summary Data': 'ExportData',
                                                'Export Image': 'ExportImage',
                                                'Download': 'ExportXML',
                                                'Filter': 'Filter',
                                                'Project Leader': 'ProjectLeader',
                                                'View': 'Read',
                                                'Share Customized': 'ShareView',
                                                'View Comments': 'ViewComments',
                                                'View Underlying Data': 'ViewUnderlyingData',
                                                'Web Edit': 'WebAuthoring',
                                                'Save': 'Write'
                                                }

    #
    # Object helpers and setter/getters
    #

    def enable_logging(self, logger_obj):
        if isinstance(logger_obj, Logger):
            self.__logger = logger_obj

    def log(self, l):
        if self.__logger is None:
            self.__logger.log(l)

    def get_last_error(self):
        self.log(self.__last_error)
        return self.__last_error

    def set_last_error(self, error):
        self.__last_error = error

    # Method to read file in x MB chunks for upload, 10 MB by default (1024 bytes = KB, * 1024 = MB, * 10)
    @staticmethod
    def __read_file_in_chunks(file_object, chunk_size=(1024 * 1024 * 10)):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    #
    # REST API Helper Methods
    #

    def build_api_url(self, call, login=False):
        if login == 'login':
            return self.__server + "/api/2.0/" + call
        else:
            return self.__server + "/api/2.0/sites/" + self.__site_luid + "/" + call

    # URI is different form actual URL you need to load a particular view in iframe
    @staticmethod
    def convert_view_content_url_to_embed_url(content_url):
        split_url = content_url.split('/')
        return 'views/' + split_url[0] + "/" + split_url[2]

    # Generic method for XML lists for the "query" actions to name -> id dict
    @staticmethod
    def convert_xml_list_to_name_id_dict(lxml_obj):
        d = {}
        for element in lxml_obj:
            e_id = element.get("id")
            name = element.get("name")
            d[name] = e_id
        return d

    #
    # Internal REST API Helpers (mostly XML definitions that are reused between methods)
    #
    @staticmethod
    def __build_site_request_xml(site_name=False, content_url=False, admin_mode=False, user_quota=False,
                                 storage_quota=False, disable_subscriptions=False, state=False):
        request = '<tsRequest><site '
        if site_name is not False:
            request = request + 'name="{}" '.format(site_name)
        if content_url is not False:
            request = request + 'contentUrl="{}" '.format(content_url)
        if admin_mode is not False:
            request = request + 'adminMode="{}" '.format(admin_mode)
        if user_quota is not False:
            request = request + 'userQuota="{}" '.format(user_quota)
        if state is not False:
            request = request + 'state="{}" '.format(state)
        if storage_quota is not False:
            request = request + 'storageQuota="{}" '.format(storage_quota)
        if disable_subscriptions is not False:
            request = request + 'disableSubscriptions="{}" '.format(disable_subscriptions)
        request = request + '/></tsRequest>'
        return request

    def __build_connection_update_xml(self, new_server_address=False, new_server_port=False,
                                      new_connection_username=False, new_connection_password=False):
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


    #
    # Sign-in and Sign-out
    #

    def signin(self):
        if self.__site == 'default':
            login_payload = '<tsRequest><credentials name="{}" password="{}" ><site /></credentials></tsRequest>'.format(
                self.__username, self.__password)
        else:
            login_payload = '<tsRequest><credentials name="{}" password="{}" ><site contentUrl="{}" /></credentials></tsRequest>'.format(
                self.__username, self.__password, self.__site)
        url = self.build_api_url("auth/signin", 'login')
        self.log(url)
        api = RestXmlRequest(url, False, self.__logger)
        api.set_xml_request(login_payload)
        api.set_http_verb('post')
        self.log(login_payload)
        api.request_from_api(0)
        self.log(api.get_raw_response())
        xml = api.get_response()
        credentials_element = xml.xpath('//t:credentials', namespaces=self.__ns_map)
        self.__token = credentials_element[0].get("token")
        self.log("Token is " + self.__token)
        self.__site_luid = credentials_element[0].xpath("//t:site", namespaces=self.__ns_map)[0].get("id")
        self.log("Site ID is " + self.__site_luid)

    def signout(self):
        url = self.build_api_url("auth/signout", "login")
        self.log(url)
        api = RestXmlRequest(url, False, self.__logger)
        api.set_http_verb('post')
        api.request_from_api()
        self.log('Signed out successfully')

    #
    # HTTP "verb" methods. These actually communicate with the RestXmlRequest object to place the requests
    #

    # baseline method for any get request. appends to base url
    def query_resource(self, url_ending, login=False):
        api_call = self.build_api_url(url_ending, login)
        api = RestXmlRequest(api_call, self.__token, self.__logger)
        self.log("query_resource() results in " + api_call)
        api.request_from_api()
        xml = api.get_response().getroot()  # return Element rather than ElementTree
        return xml

    def send_post_request(self, url):
        api = RestXmlRequest(url, self.__token, self.__logger)
        api.set_http_verb('post')
        api.request_from_api(0)
        xml = api.get_response().getroot()  # return Element rather than ElementTree
        return xml

    def send_add_request(self, url, request):
        self.log("Adding via send_add_request() on {}".format(url))
        self.log("Using this request : {}".format(request))
        api = RestXmlRequest(url, self.__token, self.__logger)
        api.set_xml_request(request)
        api.set_http_verb('post')
        api.request_from_api(0)  # Zero disables paging, for all non queries
        xml = api.get_response().getroot()  # return Element rather than ElementTree
        return xml

    def send_update_request(self, url, request):
        api = RestXmlRequest(url, self.__token, self.__logger)
        api.set_xml_request(request)
        api.set_http_verb('put')
        api.request_from_api(0)  # Zero disables paging, for all non queries
        return api.get_response()

    def send_delete_request(self, url):
        api = RestXmlRequest(url, self.__token, self.__logger)
        api.set_http_verb('delete')
        try:
            api.request_from_api(0)  # Zero disables paging, for all non queries
        except Exception as e:
            self.log(str(api.get_last_url_request()))
            self.log(str(api.get_last_response_headers()))
            raise

    def send_publish_request(self, url, request, boundary_string):
        api = RestXmlRequest(url, self.__token, self.__logger)
        api.set_publish_content(request, boundary_string)
        api.set_http_verb('post')
        api.request_from_api(0)
        xml = api.get_response().getroot()  # return Element rather than ElementTree
        return xml

    def send_append_request(self, url, request, boundary_string):
        api = RestXmlRequest(url, self.__token, self.__logger)
        api.set_publish_content(request, boundary_string)
        api.set_http_verb('put')
        api.request_from_api(0)
        xml = api.get_response().getroot()  # return Element rather than ElementTree
        return xml

    #
    # Basic Querying / Get Methods
    #

    def query_datasources(self):
        return self.query_resource("datasources")

    def query_datasource_luid_by_name(self, name):
        datasources = self.query_datasources()
        datasource = datasources.xpath('//t:datasource[@name="{}"]'.format(name), namespaces=self.__ns_map)
        if len(datasource) == 1:
            return datasource[0].get("id")
        else:
            raise NoMatchFoundException("No datasource found with name " + name)

    def query_datasource_by_luid(self, luid):
        return self.query_resource('datasources/{}'.format(luid))

    def query_datasource_permissions_by_luid(self, luid):
        return self.query_resource('datasources/{}/permissions'.format(luid))

    def query_datasource_permissions_by_name(self, name):
        datasource_luid = self.query_datasource_luid_by_name(name)
        return self.query_datasource_permissions_by_luid(datasource_luid)

    def query_groups(self):
        return self.query_resource("groups")

    # No basic verb for querying a single group, so run a query_groups
    def query_group_by_luid(self, group_luid):
        groups = self.query_groups()
        group = groups.xpath('//t:group[@id="{}"]'.format(group_luid), namespaces=self.__ns_map)
        if len(group) == 1:
            return group[0]
        else:
            raise NoMatchFoundException("No group found with luid " + group_luid)

    def query_group_luid_by_name(self, name):
        groups = self.query_groups()
        group = groups.xpath('//t:group[@name="{}"]'.format(name), namespaces=self.__ns_map)
        if len(group) == 1:
            return group[0].get("id")
        else:
            raise NoMatchFoundException("No group found with name " + name)

    def query_projects(self):
        return self.query_resource("projects")

    def query_project_by_luid(self, luid):
        projects = self.query_projects()
        project = projects.xpath('//t:project[@id="{}"]'.format(luid), namespaces=self.__ns_map)
        if len(project) == 1:
            return project[0]
        else:
            raise NoMatchFoundException("No project found with luid " + luid)

    def query_project_luid_by_name(self, name):
        projects = self.query_projects()
        project = projects.xpath('//t:project[@name="{}"]'.format(name), namespaces=self.__ns_map)
        if len(project) == 1:
            return project[0].get("id")
        else:
            raise NoMatchFoundException("No project found with name " + name)

    def query_project_permissions_by_luid(self, luid):
        return self.query_resource("projects/{}/permissions".format(luid))

    def query_project_permissions_by_name(self, name):
        project_luid = self.query_project_luid_by_name(name)
        return self.query_project_permissions_by_luid(project_luid)

    # Site queries don't have the site portion of the URL, so login option gets correct format
    def query_sites(self):
        return self.query_resource("sites/", 'login')

    # Methods for getting info about the sites, since you can only query a site when you are signed into it
    # Return list of all site luids

    def query_all_site_luids(self):
        sites = self.query_sites()
        site_luids = []
        for site in sites:
            site_luids.append(site.get("id"))
        return site_luids

    # Return list of all site contentUrls
    def query_all_site_content_urls(self):
        sites = self.query_sites()
        site_content_urls = []
        for site in sites:
            site_content_urls.append(site.get("contentUrl"))
        return site_content_urls

        # Return list of all site names


    def query_all_site_names(self):
        sites = self.query_sites()
        site_names = []
        for site in sites:
            site_names.append(site.get("name"))
        return site_names


    def query_site_luid_by_site_name(self, site_name):
        site_names = self.query_all_site_names()
        site_luids = self.query_all_site_luids()
        if site_name in site_names:
            return site_luids[site_names.index(site_name)]
        else:
            raise NoMatchFoundException("Did not find site with name '" + site_name + "' on the server")

    def query_site_luid_by_site_content_url(self, site_content_url):
        site_content_urls = self.query_all_site_content_urls()
        site_luids = self.query_all_site_luids()
        if site_content_url in site_content_urls:
            return site_luids[site_content_urls.index(site_content_url)]
        else:
            raise NoMatchFoundException("Did not find site with ContentUrl '" + site_content_url + "' on the server")

    def query_site_content_url_by_site_name(self, site_name):
        site_names = self.query_all_site_names()
        site_content_urls = self.query_all_site_content_urls()
        if site_name in site_names:
            return site_content_urls[site_names.index(site_name)]
        else:
            raise NoMatchFoundException("Did not find site with name '" + site_name + "' on the server")

    # You can only query a site you have logged into this way. Better to use methods that run through query_sites
    def query_current_site(self):
        return self.query_resource("sites/" + self.__site_luid, 'login')

    def query_user_by_luid(self, luid):
        return self.query_resource("users/{}".format(luid))

    def query_users(self):
        return self.query_resource("users")

    def query_user_luid_by_username(self, username):
        users = self.query_users()
        user = users.xpath('//t:user[@name="{}"]'.format(username), namespaces=self.__ns_map)
        if len(user) == 1:
            return user[0].get("id")
        else:
            raise NoMatchFoundException("No user found with username " + username)

    def query_users_in_group_by_luid(self, luid):
        return self.query_resource("groups/{}/users".format(luid))

    def query_users_in_group_by_name(self, group_name):
        luid = self.query_group_luid_by_name(group_name)
        return self.query_users_in_group_by_luid(luid)

    def query_workbook_by_luid(self, luid):
        return self.query_resource("workbooks/{}".format(luid))

    def query_workbooks_for_user_by_luid(self, luid):
        return self.query_resource("users/{}/workbooks".format(luid))

    def query_workbook_for_username_by_workbook_name(self, username, wb_name):
        workbooks = self.query_workbooks_by_username(username)
        workbook = workbooks.xpath('//t:workbook[@name="{}"]'.format(wb_name), namespaces=self.__ns_map)
        if len(workbook) == 1:
            wb_luid = workbook[0].get("id")
            return self.query_workbook_by_luid(wb_luid)
        else:
            raise NoMatchFoundException("No workbook found for username " + username + " named " + wb_name)

    def query_workbooks_by_username(self, username):
        user_luid = self.query_user_luid_by_username(username)
        return self.query_workbooks_for_user_by_luid(user_luid)

    def query_workbook_permissions_for_username_by_workbook_name(self, username, wb_name):
        wb_luid = self.query_workbook_for_username_by_workbook_name(username, wb_name)
        return self.query_workbook_permissions_by_luid(wb_luid)

    # Need to figure how to use this to update the connections in a workbook. Seems to return
    # LUIDs for connections and the datatypes, but no way to distinguish them
    # Ask Tyler Doyle?

    def query_workbook_connections_for_username_by_workbook_name(self, username, wb_name):
        wb_luid = self.query_workbook_for_username_by_workbook_name(username, wb_name)
        return self.query_workbook_connections_by_luid(wb_luid)

    #
    # Create / Add Methods
    #

    def add_user_by_username(self, username, site_role='Unlicensed'):
        # Check to make sure role that is passed is a valid role in the API
        try:
            self.__site_roles.index(site_role)
        except:
            raise Exception(site_role + " is not a valid site role in Tableau Server")
        # See if username already exists, if so, don't do anything
        try:
            username_luid = self.query_user_luid_by_username(username)
            self.log("Username " + username + " already exists on the server as " + username_luid)
            raise AlreadyExistsException("Username " + username + " already exists on the server as " + username_luid,
                                         username_luid)
        # If there is no match, add the user
        except NoMatchFoundException:
            self.log("Adding " + username)
            add_request = '<tsRequest><user name="{}" siteRole="{}" /></tsRequest>'.format(username, site_role)
            self.log(add_request)
            url = self.build_api_url('users')
            self.log(url)
            new_user = self.send_add_request(url, add_request)
            new_user_luid = new_user.xpath('//t:user', namespaces=self.__ns_map)[0].get("id")
            return new_user_luid
        except:
            raise

            # This is "Add User to Site", since you must be logged into a site


    def add_user(self, username, fullname, site_role='Unlicensed', password=False, email=False):
        # Add username first, then update with full name
        add_request = '<tsRequest><user name="{}" siteRole="{}" /></tsRequest>'.format(username, site_role)
        self.log(add_request)
        url = self.build_api_url('users')
        self.log(url)
        try:
            new_user_luid = self.add_user_by_username(username)
            self.update_user(new_user_luid, fullname, password, email)
            return new_user_luid
        except AlreadyExistsException as e:
            self.log("Username " + username + " already exists on the server with luid " + e.existing_luid)
            return e.existing_luid
            # return self.update_user(new_user_luid,fullname,password,email)


    def create_group(self, group_name):
        add_request = '<tsRequest><group name="{}" /></tsRequest>'.format(group_name)
        self.log(add_request)
        url = self.build_api_url("groups")
        self.log(url)
        new_group = self.send_add_request(url, add_request)
        return new_group.xpath('//t:group', namespaces=self.__ns_map)[0].get("id")


    def create_project(self, project_name, project_desc=False):
        add_request = '<tsRequest><project name="{}" '.format(project_name)
        if project_desc != False:
            add_request = add_request + 'description="{}"'.format(project_desc)
        add_request = add_request + " /></tsRequest>"
        self.log(add_request)
        url = self.build_api_url("projects")
        new_project = self.send_add_request(url, add_request)
        return new_project.xpath('//t:project', namespaces=self.__ns_map)[0].get("id")

        # Both SiteName and ContentUrl must be unique to add a site


    def create_site(self, site_name, content_url, admin_mode=False, user_quota=False, storage_quota=False,
                    disable_subscriptions=False):
        # Both SiteName and ContentUrl must be unique to add a site
        site_names = self.query_all_site_names()
        if site_name in site_names:
            raise AlreadyExistsException("Site Name '" + site_name + "' already exists on server", site_name)
        site_content_urls = self.query_all_site_content_urls()
        if content_url in site_content_urls:
            raise AlreadyExistsException("Content URL '" + content_url + "' already exists on server", content_url)
        add_request = self.__build_site_request_xml(site_name, content_url, admin_mode, user_quota, storage_quota,
                                                    disable_subscriptions)
        url = self.build_api_url("sites/", 'login')  # Site actions drop back out of the site ID hierarchy like a login
        self.log(add_request)
        self.log(url)
        new_site = self.send_add_request(url, add_request)
        return new_site.xpath('//t:site', namespaces=self.__ns_map)[0].get("id")

        # Take a single user_luid string or a collection of luid_strings


    def add_users_to_group_by_luid(self, user_luid_s, group_luid):
        # Check that group exists and IS NOT "All Users", which cannot be added to
        try:
            self.log("Getting group name for {}".format(group_luid))
            group = self.query_group_by_luid(group_luid)
            self.log("Name for {} is {}".format(group_luid, group.get("name")))
        except:
            raise NoMatchFoundException("Group {} does not exist on server".format(group_luid))

        if group.get("name") != 'All Users':
            # Check that user_luid exists
            try:
                # Test for str vs. collection
                if isinstance(user_luid_s, (str, unicode)):
                    user_luids = [user_luid_s]  # Make single into a collection
                else:
                    user_luids = user_luid_s
                for user_luid in user_luids:
                    self.query_user_by_luid(user_luid)
                    add_request = '<tsRequest><user id="{}" /></tsRequest>'.format(user_luid)
                    self.log(add_request)
                    url = self.build_api_url("groups/{}/users/".format(group_luid))
                    self.log(url)
                    self.send_add_request(url, add_request)
            except:
                raise NoMatchFoundException("User {} does not exist on server".format(user_luid))
        else:
            self.log("Skipping add action to 'All Users' group")


        # def add_workbook_permissions(self,)
            #
            # Update Methods
            #

    def update_user(self, user_luid, full_name=False, site_role=False, password=False,
                            email=False):

        # Check if user_luid exists
        self.query_user_by_luid(user_luid)
        update_request = "<tsRequest><user "
        if full_name is not False:
            update_request = update_request + 'fullName="{}" '.format(full_name)
        if site_role is not False:
            update_request = update_request + 'siteRole="{}" '.format(site_role)
        if email is not False:
            update_request = update_request + 'email="{}" '.format(email)
        if password is not False:
            update_request = update_request + 'password="{}" '.format(password)
        update_request = update_request + "/></tsRequest>"
        url = self.build_api_url("users/{}".format(user_luid))
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url, update_request)

    def update_datasource_by_luid(self, datasource_luid, new_datasource_name=False, new_project_luid=False,
                                  new_owner_luid=False):
        # Check if datasource_luid exists
        self.query_datasource_by_luid(datasource_luid)
        update_request = "<tsRequest><datasource"
        if new_datasource_name != False:
            update_request = update_request + ' name="{}" '.format(new_datasource_name)
        update_request = update_request + ">"  # Complete the tag no matter what
        if new_project_luid != False:
            update_request = update_request + '<project id="{}"/>'.format(new_project_luid)
        if new_owner_luid != False:
            update_request = update_request + '<owner id="{}"/>'.format(new_owner_luid)
        update_requeest = update_request + "</datasource></tsRequest?"
        url = self.build_api_url("datasources/{}".format(datasource_luid))
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url, update_request)

    def update_datasource_connection_by_luid(self, datasource_luid, new_server_address=False, new_server_port=False,
                                             new_connection_username=False, new_connection_password=False):
        # Check if datasource_luid exists
        self.query_datasource_by_luid(datasource_luid)
        update_request = self.__build_connection_update_xml(new_server_address, new_server_port, new_connection_username,
                                                            new_connection_password)
        url = self.build_api_url("datasources/{}/connection".format(datasource_luid))
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url, update_request)

    # Local Authentication update group
    def update_group_by_luid(self, group_luid, new_group_name):
        # Check that group_luid exists
        self.query_group_by_luid(group_luid)
        update_request = '<tsRequest><group name="{}" /></tsRequest>'.format(new_group_name)
        url = self.build_api_url("groups/{}".format(group_luid))
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url, update_request)

        # AD group sync. Must specify the domain and the default site role for imported users

    def sync_ad_group_by_luid(self, group_luid, ad_group_name, ad_domain, default_site_role, sync_as_background='true'):
        if sync_as_background not in ['true', 'false']:
            raise InvalidOptionException(
                "'{}' is not a valid option for sync_as_background. Use 'true' or 'false'".format(sync_as_background))
        if default_site_role not in self.__site_roles:
            raise InvalidOptionException("'{}' is not a valid site role in Tableau".format(default_site_role))
        # Check that the group exists
        self.query_group_by_luid(group_luid)
        update_request = '<tsRequest><group name="{}"><import source="ActiveDirectory" domainName="{}" siteRole="{}" /></group></tsRequest>'.format(
            ad_group_name, ad_domain, default_site_role)
        url = self.build_api_url("groups/{}".format(group_luid) + "?asJob={}".format(sync_as_background))
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url, update_request)

    def update_project_by_luid(self, project_luid, new_project_name=False, new_project_description=False):
        # Check that project_luid exists
        self.query_project_by_luid(project_luid)
        update_request = '<tsRequest><project '
        if new_project_name is not False:
            update_request = update_request + 'name="{}" '.format(new_project_name)
        if new_project_description is not False:
            update_request = update_request + 'description="{}"'.format(new_project_description)
        update_request = update_request + "/><tsRequest>"
        self.log(update_request)
        url = self.build_api_url("projects")
        self.log(url)
        return self.send_update_request(url, update_request)

    def update_project_by_name(self, project_name, new_project_name=False, new_project_description=False):
        project_luid = self.query_project_luid_by_name(project_name)
        return self.update_project_by_luid(project_luid, new_project_name, new_project_description)

        # Can only update the site you are signed into, so take site_luid from the object

    def update_current_site(self, site_name=False, content_url=False, admin_mode=False, user_quota=False,
                            storage_quota=False, disable_subscriptions=False, state=False):
        update_request = self.__build_site_request_xml(site_name, content_url, admin_mode, user_quota, storage_quota,
                                                       disable_subscriptions, state)
        url = self.build_api_url("{}".format(self.buildApiUrl))
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url, update_request)

        # Docs do not list a name update function. Is that true?

    def update_workbook_by_luid(self, workbook_luid, new_project_luid=False, new_owner_luid=False):
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
        url = self.build_api_url("workbooks")
        self.log(url)
        return self.send_update_request(url, update_request)

    # To do this, you need the workbook's connection_luid. Seems to only come from "Query Workbook Connections", which does
    # not return any names, just types and LUIDs
    def update_workbook_connection_by_luid(self, wb_luid, connection_luid, new_server_address=False, new_server_port=False,
                                           new_connection_username=False, new_connection_password=False):
        # Check if datasource_luid exists
        self.query_workbook_by_luid(wb_luid)
        self.query_workbook_connection()
        update_request = self.__build_connection_update_xml(new_server_address, new_server_port, new_connection_username,
                                                            new_connection_password)
        url = self.build_api_url("workbooks/{}/connections/{}".format(wb_luid, connection_luid))
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url, update_request)

        # Creates a single XML block based on capabilities_dict that is passed in
        # Capabilities dict like { capName : 'Allow', capName : 'Deny'...}


    def __create_grantee_capabilities_xml(self, capabilities_dict, grantee_luid, grantee_type='group'):
        if grantee_type not in ['group', 'user']:
            raise InvalidOptionException("grantee_type can only be 'group' or 'user'")

        xml = '<granteeCapabilities><{} id="{}" />\n<capabilities>'.format(grantee_type, grantee_luid)
        for cap in capabilities_dict:
            # Check it is a valid capability
            if cap not in (self.__workbook_capabilities, self.__datasource_capabilities):
                raise InvalidOptionException("'{}' is not an available capability in the REST API".format(cap))
            # Check that it is either 'Allow' or 'Deny'
            if capabilities_dict[cap] not in ['Allow', 'Deny']:
                raise InvalidOptionException(
                    "'{}' is not acceptable as a mode, only 'Allow' or 'Deny' work".format(capabilities_dict[cap]))
            xml = xml + '<capability name="{}" mode="{}" />'.format(cap, capabilities_dict[cap])
        xml = xml + '</granteeCapabilities>'
        return xml

    # Can take single group_luid or list and will assign the same capabilities to each group sent in


def update_workbook_capabilities_for_groups_by_luid(self, wb_luid, group_luid_s, capabilities_dict):
    ##
    ## Delete methods
    ##

    # Can take collection or luid_string        
    def delete_datasources_by_luid(self, datasource_luid_s):
        if isinstance(datasource_luid_s, (str, unicode)):
            datasource_luids = [datasource_luid_s]  # Make single into a collection
        else:
            datasource_luids = datasource_luid_s
        for datasource_luid in datasource_luids:
            # Check if datasource_luid exists
            self.query_datasource_by_luid(datasource_luid)
            url = self.build_api_url("datasources/{}".format(datasource_luid))
            self.log("Deleting datasource via  " + url)
            self.send_delete_request(url)

    def delete_projects_by_luid(self, project_luid_s):
        if isinstance(project_luid_s, (str, unicode)):
            project_luids = [project_luid_s]  # Make single into a collection
        else:
            project_luids = project_luid_s
        for project_luid in project_luids:
            # Check if project_luid exists
            self.query_project_by_luid(project_luid)
            url = self.build_api_url("projects/{}".format(project_luid))
            self.log("Deleting project via  " + url)
            self.send_delete_request(url)

    # Can only delete a site that you have signed into
    def delete_current_site(self):
        url = self.build_api_url("sites/{}".format(self.__site_luid), 'login')
        self.log("Deleting site via " + url)
        self.send_delete_request(url)

    # Can take collection or luid_string
    def delete_workbooks_by_luid(self, wb_luid_s):
        if isinstance(wb_luid_s, (str, unicode)):
            wb_luids = [wb_luid_s]  # Make single into a collection
        else:
            wb_luids = wb_luid_s
        for wb_luid in wb_luids:
            # Check if workbook_luid exists
            self.query_workbook_by_luid(wb_luid)
            url = self.build_api_url("workbooks/{}".format(wb_luid))
            self.log("Deleting workbook via " + url)
            self.send_delete_request(url)

    # Can take collection or luid_string
    def delete_workbooks_from_user_favorites_by_luid(self, wb_luid_s, user_luid):
        # Check if users exist
        self.query_user_by_luid(user_luid)
        # Check if workbook_luid exists
        if isinstance(wb_luid_s, (str, unicode)):
            wb_luids = [wb_luid_s]  # Make single into a collection
        else:
            wb_luids = wb_luid_s
        for wb_luid in wb_luids:
            # Check if workbook_luid exists
            self.query_workbook_by_luid(wb_luid)
            url = self.build_api_url("favorites/{}/workbooks/{}".format(user_luid, wb_luid))
            self.log("Removing workbook from favorites via " + url)
            self.send_delete_request(url)

    # Can take collection or string user_luid string
    def remove_users_from_group_by_luid(self, user_luid_s, group_luid):
        # Check if user and group luids exist
        self.query_group_by_luid(group_luid)

        # Check if user_luid exists
        if isinstance(user_luid_s, (str, unicode)):
            user_luids = [user_luid_s]  # Make single into a collection
        else:
            user_luids = user_luid_s
        for user_luid in user_luids:
            self.query_user_by_luid(user_luid)
            url = self.build_api_url("groups/{}/users/{}".format(user_luid, group_luid))
            self.log("Removing user from group via DELETE on " + url)
            self.send_delete_request(url)

    # Can take collection or single user_luid string
    def remove_users_from_site_by_luid(self, user_luid_s):
        # Check if user_luid exists
        if isinstance(user_luid_s, (str, unicode)):
            user_luids = [user_luid_s]  # Make single into a collection
        else:
            user_luids = user_luid_s
        for user_luid in user_luids:
            self.query_user_by_luid(user_luid)
            url = self.build_api_url("users/{}".format(user_luid))
            self.log("Removing user from site via DELETE on " + url)
            self.send_delete_request(url)

    ### Permissions delete -- this is "Delete Workbook Permissions" for users or groups
    def delete_workbook_capability_for_user_by_luid(self, wb_luid, user_luid, capability_name, capability_mode):
        url = self.build_api_url(
            "workbooks/{}/permissions/users/{}/{}/{}".format(wb_luid, user_luid, capability_name, capability_mode))
        self.log("Deleting workbook capability via this URL: " + url)
        self.__send_delete_request(url)

    def delete_workbook_capability_for_group_by_luid(self, wb_luid, group_luid, capability_name, capability_mode):
        url = self.build_api_url(
            "workbooks/{}/permissions/groups/{}/{}/{}".format(wb_luid, group_luid, capability_name, capability_mode))
        self.log("Deleting workbook capability via this URL: " + url)
        self.__send_delete_request(url)

    ### Permissions delete -- this is "Delete datasource Permissions" for users or groups
    def delete_datasource_capability_for_user_by_luid(self, ds_luid, user_luid, capability_name, capability_mode):
        url = self.build_api_url(
            "datasources/{}/permissions/users/{}/{}/{}".format(ds_luid, user_luid, capability_name, capability_mode))
        self.log("Deleting datasource capability via this URL: " + url)
        self.__send_delete_request(url)

    def delete_datasource_capability_for_group_by_luid(self, ds_luid, group_luid, capability_name, capability_mode):
        url = self.build_api_url(
            "datasources/{}/permissions/groups/{}/{}/{}".format(ds_luid, group_luid, capability_name, capability_mode))
        self.log("Deleting datasource capability via this URL: " + url)
        self.__send_delete_request(url)

    ##
    ### Publish methods -- workbook, datasources, file upload
    ##

    ''' Publish process can go two way: 
        (1) Initiate File Upload (2) Publish workbook/datasource (less than 64MB) 
        (1) Initiate File Upload (2) Append to File Upload (3) Publish workbook to commit (over 64 MB)
    '''

    # You must generate a boundary string that is used both in the headers and the generated request that you post.
    # This builds a simple 30 hex digit string
    def generate_boundary_string(self):
        random_digits = [random.SystemRandom().choice('0123456789abcdef') for n in xrange(30)]
        str = "".join(random_digits)
        return str

    def publish_workbook(self, workbook_filename, workbook_name, project_luid, overwrite=False,
                         connection_username=None, connection_password=None, save_credentials=True):
        self.publish_content('workbook', workbook_filename, workbook_name, project_luid, overwrite, connection_username,
                             connection_password, save_credentials)

    def publish_datasource(self, ds_filename, ds_name, project_luid, overwrite=False, connection_username=None,
                           connection_password=None, save_credentials=True):
        self.publish_content('datasource', ds_filename, ds_name, project_luid, overwrite, connection_username,
                             connection_password, save_credentials)

    # Main method for publishing a workbook. Should intelligently decide to chunk up if necessary
    def publish_content(self, content_type, content_filename, content_name, project_luid, overwrite=False,
                        connection_username=None, connection_password=None, save_credentials=True):
        # Single upload limit in MB
        single_upload_limit = 20

        # Must be 'workbook' or 'datasource'
        if content_type not in ['workbook', 'datasource']:
            raise InvalidOptionException("content_type must be 'workbook' or 'datasource'")

        # Check if project_luid exists
        self.query_project_by_luid(project_luid)

        # Open the file to be uploaded
        try:
            content_file = open(content_filename, 'rb')
            file_size = os.path.getsize(content_filename)
            file_size_mb = float(file_size) / float(1000000)
            self.log("File {} is size {} MBs".format(content_filename, file_size_mb))
        except IOError:
            print "Error: File '" + content_filename + "' cannot be opened to upload"
            raise

        # Request type is mixed and require a boundary
        boundary_string = self.generate_boundary_string()

        # Create the initial XML portion of the request
        publish_request = "--{}\r\n".format(boundary_string)
        publish_request = publish_request + 'Content-Disposition: name="request_payload"\r\n'
        publish_request = publish_request + 'Content-Type: text/xml\r\n\r\n'
        publish_request = publish_request + '<tsRequest>\n<{} name="{}">\r\n'.format(content_type, content_name)
        if connection_username != None and connection_password != None:
            publish_request = publish_request + '<connectionCredentials name="{}" password="{}" embed="{}" />\r\n'.format(
                connection_username, connection_password, str(save_credentials).lower())
        publish_request = publish_request + '<project id="{}" />\r\n'.format(project_luid)
        publish_request = publish_request + "</{}></tsRequest>\r\n".format(content_type)
        publish_request = publish_request + "--{}".format(boundary_string)

        if content_filename.endswith('.twb'):
            file_extension = 'twb'
        elif content_filename.endswith('.twbx'):
            file_extension = 'twbx'
        elif content_filename.endswith('.tde'):
            file_extension = 'tde'
        elif content_filename.endswith('.tdsx'):
            file_extension = 'tdsx'
        elif content_filename.endswith('.twbx'):
            file_extension = 'tds'
        else:
            raise InvalidOptionException(
                "File {} does not have an acceptable extension. Should be .twb,.twbx,.tde,.tdsx,.tds".format(
                    content_filename))

        # Upload as single if less than file_size_limit MB
        if file_size_mb <= single_upload_limit:
            # If part of a single upload, this if the next portion
            self.log("Less than {} MB, uploading as a single call".format(str(single_upload_limit)))
            publish_request = publish_request + '\r\n'
            publish_request = publish_request + 'Content-Disposition: name="tableau_{}"; filename="{}"\r\n'.format(
                content_type, content_filename)
            publish_request = publish_request + 'Content-Type: application/octet-stream\r\n\r\n'

            content = content_file.read()
            # Convert utf-8 encoding to regular
            if file_extension == 'twb':
                content = content.decode('utf-8')

            publish_request = publish_request + content

            publish_request = publish_request + "\r\n\r\n--{}--".format(boundary_string)
            url = self.build_api_url("{}s").format(content_type) + "?overwrite={}".format(str(overwrite).lower())
            self.send_publish_request(url, publish_request, boundary_string)
        # Break up into chunks for upload
        else:
            self.log("Greater than 10 MB, uploading in chunks")
            upload_session_id = self.initiate_file_upload()

            for piece in self.__read_file_in_chunks(content_file):
                self.log("Appending chunk to upload session {}".format(upload_session_id))
                self.append_to_file_upload(upload_session_id, piece, content_filename)

            url = self.build_api_url("{}s").format(content_type) + "?uploadSessionId={}".format(
                upload_session_id) + "&{}Type={}".format(content_type, file_extension) + "&overwrite={}".format(
                str(overwrite).lower())
            publish_request = publish_request + "--"  # Need to finish off the last boundary
            self.log("Finishing the upload with a publish request")
            self.send_publish_request(url, publish_request, boundary_string)
            content_file.close()

    def initiate_file_upload(self):
        url = self.build_api_url("fileUploads")
        xml = self.send_post_request(url)
        file_upload = xml.xpath('//t:fileUpload', namespaces=self.__ns_map)
        return file_upload[0].get("uploadSessionId")

    # Uploads a check to an already started session
    def append_to_file_upload(self, upload_session_id, content, filename):
        boundary_string = self.generate_boundary_string()
        publish_request = "--{}\r\n".format(boundary_string)
        publish_request = publish_request + 'Content-Disposition: name="request_payload"\r\n'
        publish_request = publish_request + 'Content-Type: text/xml\r\n\r\n'
        publish_request = publish_request + "--{}\r\n".format(boundary_string)
        publish_request = publish_request + 'Content-Disposition: name="tableau_file"; filename="{}"\r\n'.format(
            filename)
        publish_request = publish_request + 'Content-Type: application/octet-stream\r\n\r\n'

        publish_request = publish_request + content

        publish_request = publish_request + "\r\n--{}--".format(boundary_string)
        url = self.build_api_url("fileUploads/{}".format(upload_session_id))
        self.send_append_request(url, publish_request, boundary_string)


# Handles all of the actual HTTP calling
class RestXmlRequest:
    def __init__(self, url, token=False, logger=None):
        self.__defined_response_types = ('xml', 'png')
        self.__defined_http_verbs = ('post', 'get', 'put', 'delete')
        self.__base_url = url
        self.__xml_request = None
        self.__token = token
        self.__raw_response = None
        self.__last_error = None
        self.__last_url_request = None
        self.__last_response_headers = None
        self.__xml_object = None
        self.__ns_map = {'t': 'http://tableausoftware.com/api'}
        self.__logger = logger
        self.__publish = False
        self.__boundary_string = None
        self.__publish_content = None

        try:
            self.set_http_verb('get')
            self.set_response_type('xml')
        except:
            raise

    def log(self, l):
        if self.__logger != None:
            self.__logger.log(l)

    def set_xml_request(self, xml_request):
        self.__xml_request = xml_request
        return True

    def set_http_verb(self, verb):
        verb = verb.lower()
        if verb in self.__defined_http_verbs:
            self.__http_verb = verb
        else:
            raise Exception('HTTP Verb ' + verb + ' is not defined for this library')

    def set_response_type(self, response_type):
        response_type = response_type.lower()
        if response_type in self.__defined_response_types:
            self.__response_type = response_type
        else:
            raise Exception('Response type ' + response_type + ' is not defined in this library')

    # Must set a boundary string when publishing
    def set_publish_content(self, content, boundary_string):
        self.__publish = True
        self.__boundary_string = boundary_string
        self.__publish_content = content

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
            self.log("XML Object Response: " + etree.tostring(self.__xml_object, pretty_print=True))
            return self.__xml_object
        else:
            return self.__raw_response

    # Internal method to handle all of the http request variations, using given library.
    # Using urllib2 with some modification, you could substitute in Requests or httplib
    # depending on preference. Must be able to do the verbs listed in self.defined_http_verbs
    # Larger requests require pagination (starting at 1), thus page_number argument can be called.
    def __make_request(self, page_number=1):
        self.log("HTTP verb is {}".format(self.__http_verb))
        url = self.__base_url
        if page_number > 0:
            url = url + "?pageNumber={}".format(str(page_number))
        self.__last_url_request = url

        # Logic to create correct request
        opener = urllib2.build_opener(urllib2.HTTPHandler)
        request = urllib2.Request(url)
        if self.__http_verb == 'delete':
            request.get_method = lambda: 'DELETE'

        if self.__http_verb == 'put' or self.__http_verb == 'post':
            if self.__xml_request != None:
                request.add_data(self.__xml_request.encode("utf8"))
            elif self.__publish_content != None:
                request.add_data(self.__publish_content)
            else:
                request.add_data("")
        if self.__http_verb == 'put':
            request.get_method = lambda: 'PUT'
        if self.__token != False:
            request.add_header('X-tableau-auth', self.__token)
        if self.__publish == True:
            request.add_header('Content-Type', 'multipart/mixed; boundary={}'.format(self.__boundary_string))

        # Need to handle binary return for image somehow
        try:
            self.log("Making REST request to Tableau Server using {}".format(self.__http_verb))
            self.log("Request URI: {}".format(url))
            if self.__xml_request != None:
                self.log("Request XML:\n{}".format(self.__xml_request))
            response = opener.open(request)
            self.__raw_response = response.read()  # Leave the UTF8 decoding to lxml
            self.log("Raw Response:\n{}".format(str(self.__raw_response)))
        except urllib2.HTTPError as e:
            self.log(str(e.code))
            self.log(str(e.reason))
            self.log(str(e.msg))
            self.log(str(e.hdrs))
            self.log(str(e.fp))
            raise
        except:
            raise

    def request_from_api(self, page_number=1):
        try:
            self.__make_request(page_number)
        except:
            raise
        if self.__response_type == 'xml':
            if self.__raw_response == '':
                return True
            utf8_parser = etree.XMLParser(encoding='utf-8')
            xml = etree.parse(StringIO(self.__raw_response), parser=utf8_parser)
            # Set the XML object to the first returned. Will be replaced if there is pagination
            self.__xml_object = xml
            for pagination in xml.xpath('//t:pagination', namespaces=self.__ns_map):

                page_number = int(pagination.get('pageNumber'))
                page_size = int(pagination.get('pageSize'))
                total_available = int(pagination.get('totalAvailable'))
                total_pages = int(math.ceil(float(total_available) / float(page_size)))
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
                    for i in xrange(2, total_pages + 1):

                        response = self.__make_request(i)  # Get next page
                        xml = etree.parse(StringIO(self.__raw_response), parser=utf8_parser)
                        for obj in xml.getroot():
                            if obj.tag != 'pagination':
                                full_xml_obj = obj
                        new_xml_text_lines = etree.tostring(full_xml_obj).split("\n")
                        a = new_xml_text_lines[1:]  # Chop first tag
                        xml_text_lines.extend(a[:-2])  # Add the newly brought in lines to the overall text lines

                for line in xml_text_lines:
                    combined_xml_string = combined_xml_string + line
                combined_xml_string = combined_xml_string + "</tsResponse>";

                self.__xml_object = etree.parse(StringIO(combined_xml_string), parser=utf8_parser)


class Logger:
    def __init__(self, filename):
        try:
            lh = open(filename, 'w')
            self.__log_handle = lh
        except IOError:
            print "Error: File '" + filename + "' cannot be opened to write for logging"
            raise

    def log(self, l):
        cur_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.__log_handle.write('{}: {} \n'.format(cur_time, str(l)))


### Exceptions                
class NoMatchFoundException(Exception):
    def __init__(self, msg):
        self.msg = msg


class AlreadyExistsException(Exception):
    def __init__(self, msg, existing_luid):
        self.msg = msg
        self.existing_luid = existing_luid


# Raised when an action is attempted that requires being signed into that site
class NotSignedInException(Exception):
    def __init__(self, msg):
        self.msg = msg


# Raise when something an option is passed that is not valid in the REST API (site_role, permissions name, etc)
class InvalidOptionException(Exception):
    def __init__(self, msg):
        self.msg = msg