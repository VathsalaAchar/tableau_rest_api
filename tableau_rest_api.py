# Python 2.x only
import urllib2

# For parsing XML responses
from lxml import etree

# StringIO helps with lxml UTF8 parsing

from StringIO import StringIO
import math
import time
import random
import os
import re
import copy
import zipfile
import shutil


class TableauRestApi:
    # Defines a class that represents a RESTful connection to Tableau Server. Use full URL (http:// or https://)
    def __init__(self, server, username, password, site_content_url=""):
        if server.find('http') == -1:
            raise InvalidOptionException('Server URL must include http:// or https://')
        self.__server = server
        self._site_content_url = site_content_url
        self.__username = username
        self.__password = password
        self.__token = None  # Holds the login token from the Sign In call
        self.__site_luid = ""
        self.__user_luid = ""
        self.__login_as_user_id = None
        self.__last_error = None
        self.__logger = None
        self.__last_response_content_type = None
        self.__luid_pattern = r"[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*"
        self.__tableau_namespace = 'http://tableausoftware.com/api'
        self.__project_caps = ('ProjectLeader', )
        self.__datasource_caps = ('ChangePermissions', 'Connect', 'Delete', 'ExportXml', 'Read', 'Write')
        self.__workbook_caps = (
            'AddComment', 'ChangeHierarchy', 'ChangePermissions', 'Delete', 'ExportData', 'ExportImage', 'ExportXml',
            'Filter', 'Read', 'ShareView', 'ViewComments', 'ViewUnderlyingData', 'WebAuthoring', 'Write')
        self.__site_roles = (
            'Interactor', 'Publisher', 'SiteAdministrator', 'Unlicensed', 'UnlicensedWithPublish', 'Viewer',
            'ViewerWithPublish', 'ServerAdministrator')
        self.__permissionable_objects = ['datasource', 'project', 'workbook']
        self.__ns_map = {'t': 'http://tableausoftware.com/api'}
        self.__server_to_rest_capability_map = {'Add Comment': 'AddComment',
                                                'Move': 'ChangeHierarchy',
                                                'Set Permissions': 'ChangePermissions',
                                                'Connect': 'Connect',
                                                'Delete': 'Delete',
                                                'View Summary Data': 'ExportData',
                                                'Export Image': 'ExportImage',
                                                'Download': 'ExportXml',
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
        if self.__logger is not None:
            self.__logger.log(l)

    def get_last_error(self):
        self.log(self.__last_error)
        return self.__last_error

    def set_last_error(self, error):
        self.__last_error = error

    # Method to handle single str or list and return a list
    @staticmethod
    def to_list(x):
        if isinstance(x, (str, unicode)):
            l = [x]  # Make single into a collection
        else:
            l = x
        return l

    # Method to read file in x MB chunks for upload, 10 MB by default (1024 bytes = KB, * 1024 = MB, * 10)
    @staticmethod
    def __read_file_in_chunks(file_object, chunk_size=(1024 * 1024 * 10)):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    # You must generate a boundary string that is used both in the headers and the generated request that you post.
    # This builds a simple 30 hex digit string
    @staticmethod
    def generate_boundary_string():
        random_digits = [random.SystemRandom().choice('0123456789abcdef') for n in xrange(30)]
        s = "".join(random_digits)
        return s

    # Convert a permission
    def convert_server_permission_name_to_rest_permission(self, permission_name):
        if permission_name in self.__server_to_rest_capability_map:
            return self.__server_to_rest_capability_map[permission_name]
        else:
            raise InvalidOptionException('{} is not a permission name on the Tableau Server'.format(permission_name))

    # 32 hex characters with 4 dashes
    def is_luid(self, val):
        if len(val) == 36:
            if re.match(self.__luid_pattern, val) is not None:
                return True
            else:
                return False
        else:
            return False

    def get_lxml_ns_prefix(self):
        return '{' + self.__ns_map['t'] + '}'

    #
    # REST API Helper Methods
    #

    def build_api_url(self, call, login=False):
        if login is True:
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
            # If list is collection, have to run one deeper
            if e_id is None:
                for list_element in element:
                    e_id = list_element.get("id")
                    name = list_element.get("name")
                    d[name] = e_id
            else:
                name = element.get("name")
                d[name] = e_id
        return d

    #
    # Internal REST API Helpers (mostly XML definitions that are reused between methods)
    #
    @staticmethod
    def __build_site_request_xml(site_name=None, content_url=None, admin_mode=None, user_quota=None,
                                 storage_quota=None, disable_subscriptions=None, state=None):
        request = '<tsRequest><site '
        if site_name is not None:
            request += 'name="{}" '.format(site_name)
        if content_url is not None:
            request += 'contentUrl="{}" '.format(content_url)
        if admin_mode is not None:
            request += 'adminMode="{}" '.format(admin_mode)
        if user_quota is not None:
            request += 'userQuota="{}" '.format(user_quota)
        if state is not None:
            request += 'state="{}" '.format(state)
        if storage_quota is not None:
            request += 'storageQuota="{}" '.format(storage_quota)
        if disable_subscriptions is not None:
            request += 'disableSubscriptions="{}" '.format(disable_subscriptions)
        request += '/></tsRequest>'
        return request

    @staticmethod
    def __build_connection_update_xml(new_server_address=None, new_server_port=None,
                                      new_connection_username=None, new_connection_password=None):
        update_request = "<tsRequest><connection "
        if new_server_address is not None:
            update_request += 'serverAddress="{}" '.format(new_server_address)
        if new_server_port is not None:
            update_request += 'serverPort="{}" '.format(new_server_port)
        if new_connection_username is not None:
            update_request += 'userName="{}" '.format(new_connection_username)
        if new_connection_username is not None:
            update_request += 'password="{}"'.format(new_connection_password)
        update_request += "/></tsRequest>"
        return update_request

    # Dict { capability_name : mode } into XML with checks for validity. Set type to 'workbook' or 'datasource'
    def build_capabilities_xml_from_dict(self, capabilities_dict, obj_type):
        if obj_type not in self.__permissionable_objects:
            error_text = 'objtype can only be "project", "workbook" or "datasource", was given {}'
            raise InvalidOptionException(error_text.format('obj_type'))
        xml = '<capabilities>\n'
        for cap in capabilities_dict:
            # Skip if the capability is set to None
            if capabilities_dict[cap] is None:
                continue
            if capabilities_dict[cap] not in ['Allow', 'Deny']:
                raise InvalidOptionException('Capability mode can only be "Allow",  "Deny" (case-sensitive)')
            if obj_type == 'project':
                if cap not in self.__datasource_caps + self.__workbook_caps + self.__project_caps:
                    raise InvalidOptionException('{} is not a valid capability in the REST API'.format(cap))
            if obj_type == 'datasource':
                # Ignore if not available for datasource
                if cap not in self.__datasource_caps:
                    self.log('{} is not a valid capability for a datasource'.format(cap))
                    continue
            if obj_type == 'workbook':
                # Ignore if not available for workbook
                if cap not in self.__workbook_caps:
                    self.log('{} is not a valid capability for a workbook'.format(cap))
                    continue
            xml += '<capability name="{}" mode="{}" />'.format(cap, capabilities_dict[cap])
        xml += '</capabilities>'
        return xml

    # Turns lxml that is returned when asking for permissions into a bunch of GranteeCapabilities objects
    def convert_capabilities_xml_into_obj_list(self, lxml_obj):
        obj_list = []
        xml = lxml_obj.xpath('//t:granteeCapabilities', namespaces=self.__ns_map)
        if len(xml) == 0:
            raise NoMatchFoundException("No granteeCapabilities tags found")
        else:
            for gcaps in xml:
                for tags in gcaps:
                    # Namespace fun
                    if tags.tag == '{}group'.format(self.get_lxml_ns_prefix()):
                        luid = tags.get('id')
                        gcap_obj = GranteeCapabilities('group', luid)
                        self.log('group {}'.format(luid))
                    elif tags.tag == '{}user'.format(self.get_lxml_ns_prefix()):
                        luid = tags.get('id')
                        gcap_obj = GranteeCapabilities('user', luid)
                        self.log('user {}'.format(luid))
                    elif tags.tag == '{}capabilities'.format(self.get_lxml_ns_prefix()):
                        for caps in tags:
                            self.log(caps.get('name') + ' : ' + caps.get('mode'))
                            gcap_obj.set_capability(caps.get('name'), caps.get('mode'))
                obj_list.append(gcap_obj)
            self.log('Gcap object list has ' + str(len(obj_list)) + ' items')
            return obj_list

    # Runs through the gcap object list, and tries to do a conversion all principals to matching LUIDs on current site
    # Use case is replicating settings from one site to another
    # Orig_site must be TableauRestApi
    def convert_gcap_obj_list_from_orig_site_to_current_site(self, gcap_obj_list, orig_site):
        new_gcap_obj_list = []
        orig_site_groups = orig_site.query_groups()
        orig_site_users = orig_site.query_users()
        orig_site_groups_dict = self.convert_xml_list_to_name_id_dict(orig_site_groups)
        orig_site_users_dict = self.convert_xml_list_to_name_id_dict(orig_site_users)

        new_site_groups = self.query_groups()
        new_site_users = self.query_users()
        new_site_groups_dict = self.convert_xml_list_to_name_id_dict(new_site_groups)
        new_site_users_dict = self.convert_xml_list_to_name_id_dict(new_site_users)
        for gcap_obj in gcap_obj_list:
            orig_luid = gcap_obj.get_luid()
            if gcap_obj.get_obj_type() == 'group':
                # Find the name that matches the LUID
                try:
                    orig_name = (key for key, value in orig_site_groups_dict.items() if value == orig_luid).next()
                except StopIteration:
                    raise NoMatchFoundException("No matching name for luid {} found on the original site".format(
                                                orig_luid))
                new_luid = new_site_groups_dict.get(orig_name)

            elif gcap_obj.get_obj_type() == 'user':
                # Find the name that matches the LUID
                try:
                    orig_name = (key for key, value in orig_site_users_dict.items() if value == orig_luid).next()
                except StopIteration:
                    raise NoMatchFoundException("No matching name for luid {} found on the original site".format(
                                                orig_luid))
                new_luid = new_site_users_dict.get(orig_name)

            new_gcap_obj = copy.copy(gcap_obj)
            if new_luid is None:
                raise NoMatchFoundException("No matching {} named {} found on the new site".format(
                                            gcap_obj.get_obj_type(), orig_name))
            new_gcap_obj.set_luid(new_luid)
            new_gcap_obj_list.append(new_gcap_obj)
        return new_gcap_obj_list

    # Determine if capabilities are already set identically (or identically enough) to skip
    @staticmethod
    def are_capabilities_obj_lists_identical(new_obj_list, dest_obj_list):
        # Grab the LUIDs of each, determine if they match in the first place

        # Create a dict with the LUID as the keys for sorting and comparison
        new_obj_dict = {}
        for obj in new_obj_list:
            new_obj_dict[obj.get_luid()] = obj

        dest_obj_dict = {}
        for obj in dest_obj_list:
            dest_obj_dict[obj.get_luid()] = obj

        # If lengths don't match, they must differ
        if len(new_obj_dict) != len(dest_obj_dict):
            return False
        else:
            # If LUIDs don't match, they must differ
            new_obj_luids = new_obj_dict.keys()
            dest_obj_luids = dest_obj_dict.keys()
            new_obj_luids.sort()
            dest_obj_luids.sort()
            if cmp(new_obj_luids, dest_obj_luids) != 0:
                return False
            # Run through each to compare
            else:
                # At this point, we know they must match up
                for luid in new_obj_luids:
                    new_obj = new_obj_dict.get(luid)
                    dest_obj = dest_obj_dict.get(luid)
                    new_obj_cap_dict = new_obj.get_capabilities_dict()
                    dest_obj_cap_dict = dest_obj.get_capabilities_dict()
                    if cmp(new_obj_cap_dict, dest_obj_cap_dict):
                        return True
                    else:
                        return False

    # Looks at LUIDs in new_obj_list, if they exist in the dest_obj, compares their gcap objects, if match returns True
    @staticmethod
    def are_capabilities_objs_identical_for_matching_luids(new_obj_list, dest_obj_list):
        # Create a dict with the LUID as the keys for sorting and comparison
        new_obj_dict = {}
        for obj in new_obj_list:
            new_obj_dict[obj.get_luid()] = obj

        dest_obj_dict = {}
        for obj in dest_obj_list:
            dest_obj_dict[obj.get_luid()] = obj

        new_obj_luids = new_obj_dict.keys()
        dest_obj_luids = dest_obj_dict.keys()

        if set(dest_obj_luids).issuperset(new_obj_luids):
            # At this point, we know the new_objs do exist on the current obj, so let's see if they are identical
            for luid in new_obj_luids:
                new_obj = new_obj_dict.get(luid)
                dest_obj = dest_obj_dict.get(luid)
                new_obj_cap_dict = new_obj.get_capabilities_dict()
                dest_obj_cap_dict = dest_obj.get_capabilities_dict()
                if cmp(new_obj_cap_dict, dest_obj_cap_dict):
                    return True
                else:
                    return False
        else:
            return False
#
    # Sign-in and Sign-out
    #

    def signin(self):
        if self._site_content_url.lower() in ['default', '']:
            login_payload = '<tsRequest><credentials name="{}" password="{}" >'.format(self.__username, self.__password)
            login_payload += '<site /></credentials></tsRequest>'
        else:
            login_payload = '<tsRequest><credentials name="{}" password="{}" >'.format(self.__username, self.__password)
            login_payload += '<site contentUrl="{}" /></credentials></tsRequest>'.format(self._site_content_url)
        url = self.build_api_url("auth/signin", login=True)
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
        self.__user_luid = credentials_element[0].xpath("//t:user", namespaces=self.__ns_map)[0].get("id")
        self.log("Site ID is " + self.__site_luid)

    def signout(self):
        url = self.build_api_url("auth/signout", login=True)
        self.log(url)
        api = RestXmlRequest(url, self.__token, self.__logger)
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
            # Return for counter
            return 1
        except RecoverableHTTPException as e:
            self.log('Non fatal HTTP Exception Response {}, Tableau Code {}'.format(e.http_code, e.tableau_error_code))
            if e.tableau_error_code in [404003, 404002]:
                self.log('Delete action did not find the resouce. Consider successful, keep going')
        except:
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

    # Used when the result is not going to be XML and you want to save the raw response as binary
    def send_binary_get_request(self, url):
        api = RestXmlRequest(url, self.__token, self.__logger)
        api.set_http_verb('get')
        api.set_response_type('binary')
        api.request_from_api(0)
        # Set this content type so we can set the file externsion
        self.__last_response_content_type = api.get_last_response_content_type()
        return api.get_response()

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

    def query_datasource_by_name(self, name):
        luid = self.query_datasource_luid_by_name(name)
        return self.query_datasource_by_luid(luid)

    # Tries to guess name or LUID
    def query_datasource(self, name_or_luid):
        # LUID
        if self.is_luid(name_or_luid):
            return self.query_datasource_by_luid(name_or_luid)
        # Name
        else:
            return self.query_datasource_by_name(name_or_luid)

    def query_datasources_in_project(self, project_name_or_luid):
        if self.is_luid(project_name_or_luid):
            project_luid = self.query_project_by_luid(project_name_or_luid)
        else:
            project_luid = self.query_project_luid_by_name(project_name_or_luid)
        datasources = self.query_datasources()
        # This brings back the datasource itself
        ds_in_project = datasources.xpath('//t:project[@id="{}"]/..'.format(project_luid), namespaces=self.__ns_map)
        return ds_in_project

    def query_datasource_permissions_by_luid(self, luid):
        return self.query_resource('datasources/{}/permissions'.format(luid))

    def query_datasource_permissions_by_name(self, name):
        datasource_luid = self.query_datasource_luid_by_name(name)
        return self.query_datasource_permissions_by_luid(datasource_luid)

    def query_datasource_permissions(self, name_or_luid):
        if self.is_luid(name_or_luid):
            return self.query_datasource_permissions_by_luid(name_or_luid)
        else:
            return self.query_datasource_permissions_by_name(name_or_luid)

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

    def query_group_by_name(self, name):
        group_luid = self.query_group_luid_by_name(name)
        return self.query_group_by_luid(group_luid)

    def query_group(self, name_or_luid):
        if self.is_luid(name_or_luid):
            return self.query_group_by_luid(name_or_luid)
        else:
            return self.query_group_by_name(name_or_luid)

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

    def query_project_by_name(self, name):
        luid = self.query_project_luid_by_name(name)
        return self.query_project_by_luid(luid)

    def query_project(self, name_or_luid):
        if self.is_luid(name_or_luid):
            return self.query_project_by_luid(name_or_luid)
        else:
            return self.query_project_by_name(name_or_luid)

    def query_project_permissions_by_luid(self, luid):
        return self.query_resource("projects/{}/permissions".format(luid))

    def query_project_permissions_by_name(self, name):
        project_luid = self.query_project_luid_by_name(name)
        return self.query_project_permissions_by_luid(project_luid)

    def query_project_permissions(self, name_or_luid):
        if self.is_luid(name_or_luid):
            return self.query_project_permissions_by_luid(name_or_luid)
        else:
            return self.query_project_permissions_by_name(name_or_luid)

    # Site queries don't have the site portion of the URL, so login option gets correct format
    def query_sites(self):
        return self.query_resource("sites/", login=True)

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
        self.log(site_names)
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
        return self.query_resource("sites/" + self.__site_luid, login=True)

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

    # This uses the logged in username
    def query_workbooks(self):
        return self.query_workbooks_for_user_by_luid(self.__user_luid)

    def query_workbook_for_username_by_workbook_name(self, username, wb_name):
        workbooks = self.query_workbooks_by_username(username)
        workbook = workbooks.xpath('//t:workbook[@name="{}"]'.format(wb_name), namespaces=self.__ns_map)
        if len(workbook) == 0:
            raise NoMatchFoundException("No workbook found for username " + username + " named " + wb_name)
        elif len(workbook) == 1:
            wb_luid = workbook[0].get("id")
            return self.query_workbook_by_luid(wb_luid)
        else:
            raise MultipleMatchesFound(len(workbook))

    def query_workbook_for_user_luid_by_workbook_name(self, user_luid, wb_name):
        workbooks = self.query_workbooks_for_user_by_luid(user_luid)
        workbook = workbooks.xpath('//t:workbook[@name="{}"]'.format(wb_name), namespaces=self.__ns_map)
        if len(workbook) == 0:
            raise NoMatchFoundException("No workbook found for user " + user_luid + " named " + wb_name)
        elif len(workbook) == 1:
            wb_luid = workbook[0].get("id")
            return self.query_workbook_by_luid(wb_luid)
        else:
            raise MultipleMatchesFound(len(workbook))

    def query_workbooks_in_project_for_username(self, project_name_or_luid, username):
        if self.is_luid(project_name_or_luid):
            project_luid = self.query_project_by_luid(project_name_or_luid)
        else:
            project_luid = self.query_project_luid_by_name(project_name_or_luid)
        workbooks = self.query_workbooks_by_username(username)
        # This brings back the workbook itself
        wbs_in_project = workbooks.xpath('//t:project[@id="{}"]/..'.format(project_luid), namespaces=self.__ns_map)
        return wbs_in_project

    def query_workbooks_in_project(self, project_name_or_luid):
        return self.query_workbooks_in_project_for_username(project_name_or_luid, self.__username)

    # Assume the current logged in user
    def query_workbook_by_name(self, wb_name):
        return self.query_workbook_for_user_luid_by_workbook_name(self.__user_luid, wb_name)

    def query_workbook_luid_by_name(self, username, wb_name):
        workbooks = self.query_workbooks_by_username(username)
        workbook = workbooks.xpath('//t:workbook[@name="{}"]'.format(wb_name), namespaces=self.__ns_map)
        if len(workbook) == 1:
            wb_luid = workbook[0].get("id")
            return wb_luid
        return NoMatchFoundException("No workbook found for username " + username + " named " + wb_name)

    def query_workbook_luid_for_username_by_workbook_name(self, username, wb_name):
        workbooks = self.query_workbooks_by_username(username)
        workbook = workbooks.xpath('//t:workbook[@name="{}"]'.format(wb_name), namespaces=self.__ns_map)
        if len(workbook) == 1:
            wb_luid = workbook[0].get("id")
            return wb_luid
        else:
            raise NoMatchFoundException("No workbook found for username " + username + " named " + wb_name)

    def query_workbooks_by_username(self, username):
        user_luid = self.query_user_luid_by_username(username)
        return self.query_workbooks_for_user_by_luid(user_luid)

    # Used the logged in username
    def query_workbook_views_by_workbook_name(self, wb_name, usage=False):
        wb_luid = self.query_workbook_luid_for_username_by_workbook_name(self.__username, wb_name)
        return self.query_workbook_views_by_luid(wb_luid, usage)

    # Set Usage to True to get usage with this
    def query_workbook_views_by_luid(self, wb_luid, usage=False):
        if usage not in [True, False]:
            raise InvalidOptionException('Usage can only be set to True or False')
        # Check workbook luid
        self.query_workbook_by_luid(wb_luid)
        return self.query_resource("workbooks/{}/views?includeUsageStatistics={}".format(wb_luid, str(usage).lower()))

    def query_workbook_permissions_by_luid(self, wb_luid):
        return self.query_resource("workbooks/{}/permissions".format(wb_luid))

    def query_workbook_permissions_for_username_by_workbook_name(self, username, wb_name):
        wb_luid = self.query_workbook_luid_for_username_by_workbook_name(username, wb_name)
        return self.query_workbook_permissions_by_luid(wb_luid)

    def query_workbook_permissions(self, name_or_luid):
        if self.is_luid(name_or_luid):
            return self.query_workbook_permissions_by_luid(name_or_luid)
        else:
            return self.query_workbook_permissions_for_username_by_workbook_name(self.__username, name_or_luid)

    def query_workbook_connections_by_luid(self, wb_luid):
        # Check the workbook exists
        self.query_workbook_by_luid(wb_luid)
        return self.query_resource("workbooks/{}/connections".format(wb_luid))

    # This should be the key to updating the connections in a workbook. Seems to return
    # LUIDs for connections and the datatypes, but no way to distinguish them
    def query_workbook_connections_for_username_by_workbook_name(self, username, wb_name):
        wb_luid = self.query_workbook_for_username_by_workbook_name(username, wb_name)
        return self.query_workbook_connections_by_luid(wb_luid)

    # Checks status of AD sync process
    def query_job_by_luid(self, job_luid):
        return self.query_resource("jobs/{}".format(job_luid))

    # Do not include file extension
    def save_workbook_view_preview_image_by_luid(self, wb_luid, view_luid, filename):
        # Check for workbook
        # self.query_workbook_by_luid(wb_luid)
        # Open the file to be saved to
        try:
            save_file = open(filename + ".png", 'wb')
            url = self.build_api_url("workbooks/{}/views/{}/previewImage".format(wb_luid, view_luid))
            image = self.send_binary_get_request(url)
            save_file.write(image)
            save_file.close()
        # You might be requesting something that doesn't exist
        except RecoverableHTTPException as e:
            self.log("Attempt to request preview image results in HTTP error {}, Tableau Code {}".format(e.http_code, e.tableau_error_code))
            raise
        except IOError:
            self.log("Error: File '" + filename + "' cannot be opened to save to")
            raise

    # Do not include file extension
    def save_workbook_preview_image(self, wb_luid, filename):
        # CHeck for workbook
        # self.query_workbook_by_luid(wb_luid)
        # Open the file to be saved to
        try:
            save_file = open(filename + '.png', 'wb')
            url = self.build_api_url("workbooks/{}/previewImage".format(wb_luid))
            image = self.send_binary_get_request(url)
            save_file.write(image)
            save_file.close()
        # You might be requesting something that doesn't exist, but unlikely
        except RecoverableHTTPException as e:
            self.log("Attempt to request preview image results in HTTP error {}, Tableau Code {}".format(e.http_code, e.tableau_error_code))
            raise
        except IOError:
            print "Error: File '" + filename + "' cannot be opened to save to"
            raise

    # Do not include file extension. Without filename, only returns the response
    def download_datasource_by_luid(self, ds_luid, filename=None):
        # Check ds existence
        # self.query_datasource_by_luid(ds_luid)
        # Open the file to be saved to
        try:
            url = self.build_api_url("datasources/{}/content".format(ds_luid))
            ds = self.send_binary_get_request(url)
            extension = None
            if self.__last_response_content_type.find('application/xml') != -1:
                extension = '.tds'
            elif self.__last_response_content_type.find('application/octet-stream') != -1:
                extension = '.tdsx'
            if extension is None:
                raise IOError('File extension could not be determined')
        except RecoverableHTTPException as e:
            self.log("download_datasource_by_luid resulted in HTTP error {}, Tableau Code {}".format(e.http_code, e.tableau_error_code))
            raise
        except:
            raise
        try:
            if filename is None:
                save_filename = 'temp_ds' + extension
            else:
                save_filename = filename + extension
            save_file = open(save_filename, 'wb')
            save_file.write(ds)
            save_file.close()
            if extension == '.tdsx':
                self.log('Detected TDSX, creating TableauPackagedFile object')
                saved_file = open(save_filename, 'rb')
                return_obj = TableauPackagedFile(saved_file, self.__logger)
                saved_file.close()
                if filename is None:
                    os.remove(save_filename)
        except IOError:
            print "Error: File '" + filename + extension + "' cannot be opened to save to"
            raise
        if extension == '.tds':
            self.log('Detected TDS, creating TableauDatasource object')
            return_obj = TableauDatasource(ds, self.__logger)

        return return_obj

    # Do not include file extension, added automatically. Without filename, only returns the response
    def download_workbook_by_luid(self, wb_luid, filename=None):
        # Check ds existence
        # self.query_workbook_by_luid(wb_luid)
        # Open the file to be saved to
        try:
            url = self.build_api_url("workbooks/{}/content".format(wb_luid))
            wb = self.send_binary_get_request(url)
            extension = None
            if self.__last_response_content_type.find('application/xml') != -1:
                extension = '.twb'
            elif self.__last_response_content_type.find('application/octet-stream') != -1:
                extension = '.twbx'
            if extension is None:
                raise IOError('File extension could not be determined')
        except RecoverableHTTPException as e:
            self.log("download_workbook_by_luid resulted in HTTP error {}, Tableau Code {}".format(e.http_code, e.tableau_error_code))
            raise
        except:
            raise
        try:
            if filename is None:
                save_filename = 'temp_wb' + extension
            else:
                save_filename = filename + extension

            save_file = open(save_filename, 'wb')
            save_file.write(wb)
            save_file.close()
            if extension == '.twbx':
                self.log('Dtected TWBX, creating TableauPackagedFile object')
                saved_file = open(save_filename, 'rb')
                return_obj = TableauPackagedFile(saved_file, self.__logger)
                #saved_file.close()
                if filename is None:
                    os.remove(save_filename)

        except IOError:
            print "Error: File '" + filename + extension + "' cannot be opened to save to"
            raise
        if extension == '.twb':
            self.log('Detected TWB, creating TableauWorkbook object')
            return_obj = TableauWorkbook(wb, self.__logger)
        return return_obj

    #
    # Create / Add Methods
    #

    def add_user_by_username(self, username, site_role='Unlicensed', update_if_exists=False):
        # Check to make sure role that is passed is a valid role in the API
        try:
            self.__site_roles.index(site_role)
        except:
            raise InvalidOptionException(site_role + " is not a valid site role in Tableau Server")

        self.log("Adding " + username)
        add_request = '<tsRequest><user name="{}" siteRole="{}" /></tsRequest>'.format(username, site_role)
        self.log(add_request)
        url = self.build_api_url('users')
        self.log(url)
        try:
            new_user = self.send_add_request(url, add_request)
            new_user_luid = new_user.xpath('//t:user', namespaces=self.__ns_map)[0].get("id")
            return new_user_luid
        # If already exists, update site role unless overridden.
        except RecoverableHTTPException as e:
            if e.http_code == 409:
                self.log("Username '{}' already exists on the server".format(username))
                if update_if_exists is True:
                    self.log('Updating {} to site role {}'.format(username, site_role))
                    self.update_user(username, site_role=site_role)
                    return self.query_user_luid_by_username(username)
                else:
                    raise AlreadyExistsException('Username already exists ', self.query_user_luid_by_username(username))
        except:
            raise

    # This is "Add User to Site", since you must be logged into a site.
    # Set "update_if_exists" to True if you want the equivalent of an 'upsert', ignoring the exceptions
    def add_user(self, username, fullname, site_role='Unlicensed', password=None, email=None, update_if_exists=False):
        # Add username first, then update with full name
        add_request = '<tsRequest><user name="{}" siteRole="{}" /></tsRequest>'.format(username, site_role)
        self.log(add_request)
        url = self.build_api_url('users')
        self.log(url)
        try:
            new_user_luid = self.add_user_by_username(username, update_if_exists=update_if_exists)
            self.update_user_by_luid(new_user_luid, fullname, site_role, password, email)
            return new_user_luid
        except AlreadyExistsException as e:
            self.log("Username '{}' already exists on the server; no updates performed".format(username))
            return e.existing_luid

    # Returns the LUID of an existing group if one already exists
    def create_group(self, group_name):
        add_request = '<tsRequest><group name="{}" /></tsRequest>'.format(group_name)
        self.log(add_request)
        url = self.build_api_url("groups")
        self.log(url)
        try:
            new_group = self.send_add_request(url, add_request)
            return new_group.xpath('//t:group', namespaces=self.__ns_map)[0].get("id")
        # If the name already exists, a HTTP 409 throws, so just find and return the existing LUID
        except RecoverableHTTPException as e:
            if e.http_code == 409:
                self.log('Group named {} already exists, finding and returning the LUID'.format(group_name))
                return self.query_group_luid_by_name(group_name)

    # Creating a synced ad group is completely different, use this method
    # The luid is only available in the Response header if bg sync. Nothing else is passed this way -- how to expose?
    def create_group_from_ad_group(self, ad_group_name, ad_domain_name, default_site_role='Unlicensed',
                                   sync_as_background=True):
        if default_site_role not in self.__site_roles:
            raise InvalidOptionException('"{}" is not an acceptable site role'.format(default_site_role))
        add_request = '<tsRequest><group name="{}">'.format(ad_group_name)
        add_request += '<import source="ActiveDirectory" domainName="{}" siteRole="{}" />'.format(ad_domain_name,
                                                                                                  default_site_role)
        add_request += '</group></tsRequest>'
        self.log(add_request)
        url = self.build_api_url("groups/?asJob={}".format(str(sync_as_background).lower()))
        self.log(url)
        response = self.send_add_request(url, add_request)
        # Response is different from immediate to background update. job ID lets you track progress on background
        if sync_as_background is True:
            job = response.xpath('//t:job', namespaces=self.__ns_map)
            return job[0].get('id')
        if sync_as_background is False:
            group = response.xpath('//t:group', namespaces=self.__ns_map)
            return group[0].get('id')

    def create_project(self, project_name, project_desc=None):
        add_request = '<tsRequest><project name="{}" '.format(project_name)
        if project_desc is not None:
            add_request += 'description="{}"'.format(project_desc)
        add_request += " /></tsRequest>"
        self.log(add_request)
        url = self.build_api_url("projects")
        try:
            new_project = self.send_add_request(url, add_request)
            return new_project.xpath('//t:project', namespaces=self.__ns_map)[0].get("id")
        except RecoverableHTTPException as e:
            if e.http_code == 409:
                self.log('Project named {} already exists, finding and returning the LUID'.format(project_name))
                return self.query_project_luid_by_name(project_name)

    # Both SiteName and ContentUrl must be unique to add a site
    def create_site(self, new_site_name, new_content_url, admin_mode=None, user_quota=None, storage_quota=None,
                    disable_subscriptions=None):
        # Both SiteName and ContentUrl must be unique to add a site
        self.log('Querying all of the site names prior to create')
        site_names = self.query_all_site_names()
        site_names_lc = []
        self.log('Attempting to create site "{}" with content_url "{}"'.format(new_site_name, new_content_url))
        for name in site_names:
            site_names_lc.append(name.lower())

        if new_site_name.lower() in site_names_lc:
            raise AlreadyExistsException("Site Name '" + new_site_name + "' already exists on server", new_site_name)
        site_content_urls = self.query_all_site_content_urls()
        if new_content_url in site_content_urls:
            raise AlreadyExistsException("Content URL '{}' already exists on server".format(new_content_url),
                                         new_content_url)
        add_request = self.__build_site_request_xml(new_site_name, new_content_url, admin_mode, user_quota,
                                                    storage_quota, disable_subscriptions)
        url = self.build_api_url("sites/", login=True)  # Site actions drop back out of the site ID hierarchy like login
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
            # Test for str vs. collection
            user_luids = self.to_list(user_luid_s)
            for user_luid in user_luids:
                add_request = '<tsRequest><user id="{}" /></tsRequest>'.format(user_luid)
                self.log(add_request)
                url = self.build_api_url("groups/{}/users/".format(group_luid))
                self.log(url)
                try:
                    self.send_add_request(url, add_request)
                except RecoverableHTTPException as e:
                    self.log("Recoverable HTTP exception {} with Tableau Error Code {}, skipping".format(str(e.http_code), e.tableau_error_code))
        else:
            self.log("Skipping add action to 'All Users' group")

    # Tags can be scalar string or list
    def add_tags_to_workbook_by_luid(self, wb_luid, tag_s):
        url = self.build_api_url("workbooks/{}/tags".format(wb_luid))

        request = "<tsRequest><tags>"
        tags = self.to_list(tag_s)
        for tag in tags:
            request += "<tag label='{}' />".format(str(tag))
        request += "</tags></tsRequest>"
        return self.send_update_request(url, request)

    def add_workbook_to_user_favorites_by_luid(self, favorite_name, wb_luid, user_luid):
        request = '<tsRequest><favorite label="{}"><workbook id="{}" />'.format(favorite_name, wb_luid)
        request += '</favorite></tsRequest>'
        url = self.build_api_url("favorites/{}".format(user_luid))
        return self.send_update_request(url, request)

    def add_view_to_user_favorites_by_luid(self, favorite_name, view_luid, user_luid):
        request = '<tsRequest><favorite label="{}"><view id="{}" />'.format(favorite_name, view_luid)
        request += '</favorite></tsRequest>'
        url = self.build_api_url("favorites/{}".format(user_luid))
        return self.send_update_request(url, request)

    # Add dict { capability_name : capability_mode } 'Allow' or 'Deny'
    # Assumes group because you should be doing all your security by groups instead of individuals
    def add_permissions_by_luids(self, obj_type, obj_luid_s, luid_s, permissions_dict, luid_type='group'):
        if luid_type not in ['group', 'user']:
            raise InvalidOptionException("luid_type can only be 'group' or 'user'")
        if obj_type not in self.__permissionable_objects:
            raise InvalidOptionException('obj_type must be "workbook","datasource" or "project"')

        luids = self.to_list(luid_s)
        obj_luids = self.to_list(obj_luid_s)

        self.log(permissions_dict)
        capabilities_xml = self.build_capabilities_xml_from_dict(permissions_dict, obj_type)
        for obj_luid in obj_luids:
            request = "<tsRequest><permissions><{} id='{}' />".format(obj_type, obj_luid)
            for luid in luids:
                request += "<granteeCapabilities><{} id='{}' />".format(luid_type, luid)
                request += capabilities_xml
                request += "</granteeCapabilities>"
            request += "</permissions></tsRequest>"
            url = self.build_api_url("{}s/{}/permissions".format(obj_type, obj_luid))
            self.send_update_request(url, request)

    def add_permissions_by_gcap_obj_list(self, obj_type, obj_luid_s, gcap_obj_list):
        if obj_type not in self.__permissionable_objects:
            raise InvalidOptionException('obj_type must be "workbook","datasource" or "project"')

        obj_luids = self.to_list(obj_luid_s)

        for obj_luid in obj_luids:
            request = "<tsRequest><permissions><{} id='{}' />".format(obj_type, obj_luid)
            for gcap_obj in gcap_obj_list:
                gcap_luid = gcap_obj.get_luid()
                gcap_obj_type = gcap_obj.get_obj_type()
                capabilities_dict = gcap_obj.get_capabilities_dict()
                capabilities_xml = self.build_capabilities_xml_from_dict(capabilities_dict, obj_type)
                request += "<granteeCapabilities><{} id='{}' />".format(gcap_obj_type, gcap_luid)
                request += capabilities_xml
                request += "</granteeCapabilities>"
            request += "</permissions></tsRequest>"
            url = self.build_api_url("{}s/{}/permissions".format(obj_type, obj_luid))
            self.send_update_request(url, request)

    #
    # Update Methods
    #

    def update_user_by_luid(self, user_luid, full_name=None, site_role=None, password=None,
                            email=None):
        update_request = "<tsRequest><user "
        if full_name is not None:
            update_request += 'fullName="{}" '.format(full_name)
        if site_role is not None:
            update_request += 'siteRole="{}" '.format(site_role)
        if email is not None:
            update_request += 'email="{}" '.format(email)
        if password is not None:
            update_request += 'password="{}" '.format(password)
        update_request += "/></tsRequest>"
        url = self.build_api_url("users/{}".format(user_luid))
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url, update_request)

    def update_user_by_username(self, username, full_name=None, site_role=None, password=None,
                                email=None):
        user_luid = self.query_user_luid_by_username(username)
        return self.update_user_by_luid(user_luid, full_name, site_role, password, email)

    def update_user(self, username_or_luid, full_name=None, site_role=None, password=None,
                    email=None):
        if self.is_luid(username_or_luid):
            return self.update_user_by_luid(username_or_luid, full_name, site_role, password, email)
        else:
            return self.update_user_by_username(username_or_luid, full_name, site_role, password, email)

    def update_datasource_by_luid(self, datasource_luid, new_datasource_name=None, new_project_luid=None,
                                  new_owner_luid=None):
        update_request = "<tsRequest><datasource"
        if new_datasource_name is not None:
            update_request = update_request + ' name="{}" '.format(new_datasource_name)
        update_request += ">"  # Complete the tag no matter what
        if new_project_luid is not None:
            update_request += '<project id="{}"/>'.format(new_project_luid)
        if new_owner_luid is not None:
            update_request += '<owner id="{}"/>'.format(new_owner_luid)
        update_request += "</datasource></tsRequest>"
        url = self.build_api_url("datasources/{}".format(datasource_luid))
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url, update_request)

    def update_datasource_by_name(self, datasource_name, new_datasource_name=None, new_project_luid=None,
                                  new_owner_luid=None):
        ds_luid = self.query_datasource_luid_by_name(datasource_name)
        return self.update_datasource_by_luid(ds_luid, new_datasource_name, new_project_luid, new_owner_luid)

    def update_datasource(self, name_or_luid, new_datasource_name=None, new_project_luid=None,
                          new_owner_luid=None):
        if self.is_luid(name_or_luid):
            return self.update_datasource_by_luid(name_or_luid, new_datasource_name, new_project_luid, new_owner_luid)
        else:
            return self.update_datasource_by_name(name_or_luid, new_datasource_name, new_project_luid, new_owner_luid)

    def update_datasource_connection_by_luid(self, datasource_luid, new_server_address=None, new_server_port=None,
                                             new_connection_username=None, new_connection_password=None):

        update_request = self.__build_connection_update_xml(new_server_address, new_server_port,
                                                            new_connection_username,
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

    def update_group_by_name(self, name, new_group_name):
        group_luid = self.query_group_luid_by_name(name)
        return self.update_group_by_luid(group_luid, new_group_name)

    def update_group(self, name_or_luid, new_group_name):
        if self.is_luid(name_or_luid):
            return self.update_group_by_luid(name_or_luid, new_group_name)
        else:
            return self.update_group_by_name(name_or_luid, new_group_name)

    # AD group sync. Must specify the domain and the default site role for imported users
    def sync_ad_group_by_luid(self, group_luid, ad_group_name, ad_domain, default_site_role, sync_as_background=True):
        if sync_as_background not in [True, False]:
            error = "'{}' passed for sync_as_background. Use True or False".format(str(sync_as_background).lower())
            raise InvalidOptionException(error)

        if default_site_role not in self.__site_roles:
            raise InvalidOptionException("'{}' is not a valid site role in Tableau".format(default_site_role))
        # Check that the group exists
        self.query_group_by_luid(group_luid)
        request = '<tsRequest><group name="{}">'.format(ad_group_name)
        request += '<import source="ActiveDirectory" domainName="{}" siteRole="{}" />'.format(ad_domain,
                                                                                              default_site_role)
        request += '</group></tsRequest>'
        url = self.build_api_url("groups/{}".format(group_luid) + "?asJob={}".format(str(sync_as_background)).lower())
        self.log(request)
        self.log(url)
        response = self.send_update_request(url, request)
        # Response is different from immediate to background update. job ID lets you track progress on background
        if sync_as_background is True:
            job = response.xpath('//t:job', namespaces=self.__ns_map)
            return job[0].get('id')
        if sync_as_background is False:
            group = response.xpath('//t:group', namespaces=self.__ns_map)
            return group[0].get('id')

    def update_project_by_luid(self, project_luid, new_project_name=None, new_project_description=None):
        # Check that project_luid exists
        self.query_project_by_luid(project_luid)
        update_request = '<tsRequest><project '
        if new_project_name is not None:
            update_request += 'name="{}" '.format(new_project_name)
        if new_project_description is not None:
            update_request += 'description="{}"'.format(new_project_description)
        update_request += "/></tsRequest>"
        self.log(update_request)
        url = self.build_api_url("projects/{}".format(project_luid))
        self.log(url)
        return self.send_update_request(url, update_request)

    def update_project_by_name(self, project_name, new_project_name=None, new_project_description=None):
        project_luid = self.query_project_luid_by_name(project_name)
        return self.update_project_by_luid(project_luid, new_project_name, new_project_description)

    def update_project(self, name_or_luid, new_project_name=None, new_project_description=None):
        if self.is_luid(name_or_luid):
            return self.update_project_by_luid(name_or_luid, new_project_name, new_project_description)
        else:
            return self.update_project_by_name(name_or_luid, new_project_name, new_project_description)

    # Can only update the site you are signed into, so take site_luid from the object
    def update_current_site(self, site_name=None, content_url=None, admin_mode=None, user_quota=None,
                            storage_quota=None, disable_subscriptions=None, state=None):
        update_request = self.__build_site_request_xml(site_name, content_url, admin_mode, user_quota, storage_quota,
                                                       disable_subscriptions, state)
        url = self.build_api_url("/")
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url, update_request)

    def update_workbook_by_luid(self, workbook_luid, new_project_luid=None, new_owner_luid=None, show_tabs=None):
        # Check that workbook exists
        self.query_workbook_by_luid(workbook_luid)
        update_request = "<tsRequest><workbook showTabs='{}'>".format(str(show_tabs).lower())
        if new_project_luid is not None:
            # Check if new project_luid exists with query
            self.query_project_by_luid(new_project_luid)
            update_request += '<project id="{}" />'.format(new_project_luid)
        if new_owner_luid is not None:
            # Check if new owner_luid exists
            self.query_user_by_luid(new_owner_luid)
            update_request += '<owner id="{}" />'.format(new_owner_luid)
        update_request += '</workbook></tsRequest>'
        self.log(update_request)
        url = self.build_api_url("workbooks/{}".format(workbook_luid))
        self.log(url)
        return self.send_update_request(url, update_request)

    # To do this, you need the workbook's connection_luid. Seems to only come from "Query Workbook Connections",
    # which does not return any names, just types and LUIDs
    def update_workbook_connection_by_luid(self, wb_luid, connection_luid, new_server_address=None,
                                           new_server_port=None,
                                           new_connection_username=None, new_connection_password=None):
        # Check if datasource_luid exists
        self.query_workbook_by_luid(wb_luid)
        self.query_workbook_connections_by_luid(connection_luid)
        update_request = self.__build_connection_update_xml(new_server_address, new_server_port,
                                                            new_connection_username,
                                                            new_connection_password)
        url = self.build_api_url("workbooks/{}/connections/{}".format(wb_luid, connection_luid))
        self.log(update_request)
        self.log(url)
        return self.send_update_request(url, update_request)

    # Creates a single XML block based on capabilities_dict that is passed in
    # Capabilities dict like { capName : 'Allow', capName : 'Deny'...}

    # Can take single group_luid or list and will assign the same capabilities to each group sent in
    # The essence of this update is that we delete the capabilities, then add them back as we want
    def update_permissions_by_luids(self, obj_type, obj_luid_s, luid_s, permissions_dict, luid_type='group'):
        obj_luids = self.to_list(obj_luid_s)
        luids = self.to_list(luid_s)
        if obj_type.lower() not in self.__permissionable_objects:
            raise InvalidOptionException('obj_type must be "project", "datasource" or "workbook"')
        # Do this object by object, so that the delete and the assign are all together
        self.log('Updating permissions for {} LUIDs'.format(str(len(obj_luids))))
        for obj_luid in obj_luids:
            try:
                self.log('Deleting all permissions for {}'.format(obj_luid))
                self.delete_all_permissions_by_luids(obj_type.lower(), obj_luid, luids)
            except InvalidOptionException as e:
                self.log(e.msg)
                raise
            self.add_permissions_by_luids(obj_type.lower(), obj_luid, luids, permissions_dict, luid_type)

    def update_permissions_by_gcap_obj_list(self, obj_type, obj_luid_s, gcap_obj_list):
        obj_luids = self.to_list(obj_luid_s)
        if obj_type.lower() not in self.__permissionable_objects:
            raise InvalidOptionException('obj_type must be "project", "datasource" or "workbook"')
        # Do this object by object, so that the delete and the assign are all together
        gcap_luids = []
        for gcap_obj in gcap_obj_list:
            gcap_luids.append(gcap_obj.get_luid())
        self.log('Updating permissions for {} LUIDs'.format(str(len(obj_luids))))
        for obj_luid in obj_luids:
            # Depending on object type, we have to do the method to get our permissions
            if obj_type == 'project':
                permissions_lxml = self.query_project_permissions(obj_luid)
            elif obj_type == 'datasource':
                permissions_lxml = self.query_datasource_permissions(obj_luid)
            elif obj_type == 'workbook':
                permissions_lxml = self.query_workbook_permissions_by_luid(obj_luid)
            else:
                raise InvalidOptionException('obj_type not set correctly')
            dest_capabilities_list = self.convert_capabilities_xml_into_obj_list(permissions_lxml)
            if self.are_capabilities_objs_identical_for_matching_luids(gcap_obj_list, dest_capabilities_list) is False:
                try:
                    self.log('Deleting all permissions for {}'.format(obj_luid))
                    self.delete_all_permissions_by_luids(obj_type.lower(), obj_luid, gcap_luids)
                except InvalidOptionException as e:
                    self.log(e.msg)
                    raise
                self.add_permissions_by_gcap_obj_list(obj_type.lower(), obj_luid, gcap_obj_list)
            else:
                self.log('Skipping update because permissions on object {} already match'.format(obj_luid))

    # Special permissions methods
    # Take the permissions from one object (project most likely) and assign to other content
    # Requires clearing all permissions on an object
    def replicate_content_permissions(self, obj_luid, obj_type, dest_luid_s, dest_type):
        dest_obj_luids = self.to_list(dest_luid_s)
        if obj_type.lower() not in self.__permissionable_objects:
            raise InvalidOptionException('obj_type must be "project", "datasource" or "workbook"')
        if dest_type.lower() not in self.__permissionable_objects:
            raise InvalidOptionException('dest_type must be "project", "datasource" or "workbook"')
        # Depending on object type, we have to do the method to get our permissions
        if obj_type == 'project':
            permissions_lxml = self.query_project_permissions(obj_luid)
        elif obj_type == 'datasource':
            permissions_lxml = self.query_datasource_permissions(obj_luid)
        elif obj_type == 'workbook':
            permissions_lxml = self.query_workbook_permissions_by_luid(obj_luid)
        else:
            raise InvalidOptionException('obj_type not set correctly')

        capabilities_list = self.convert_capabilities_xml_into_obj_list(permissions_lxml)
        for dest_obj_luid in dest_obj_luids:
            # Grab the destination permissions too, so we can compare and skip if already identical
            if dest_type == 'project':
                dest_permissions_lxml = self.query_project_permissions(dest_obj_luid)
            elif dest_type == 'datasource':
                dest_permissions_lxml = self.query_datasource_permissions(dest_obj_luid)
            elif dest_type == 'workbook':
                dest_permissions_lxml = self.query_workbook_permissions_by_luid(dest_obj_luid)
            else:
                raise InvalidOptionException('obj_type not set correctly')
            dest_capabilities_list = self.convert_capabilities_xml_into_obj_list(dest_permissions_lxml)
            if self.are_capabilities_obj_lists_identical(capabilities_list, dest_capabilities_list) is False:
                # Delete all first clears the object to have them added
                self.delete_all_permissions_by_luids(dest_type, dest_obj_luid)
                # Add each set of capabilities to the cleared object
                self.add_permissions_by_gcap_obj_list(dest_type, dest_obj_luid, capabilities_list)
            else:
                self.log("Permissions matched, no need to update. Moving to next")

    # Pulls the permissions from the project, then applies them to all the content in the project
    def sync_project_permissions_to_contents(self, project_name_or_luid):
        if self.is_luid(project_name_or_luid):
            project_luid = project_name_or_luid
        else:
            project_luid = self.query_project_luid_by_name(project_name_or_luid)
        wbs_in_project = self.query_workbooks_in_project(project_name_or_luid)
        datasources_in_project = self.query_datasources_in_project(project_name_or_luid)
        self.log('Replicating permissions down to workbooks')
        wb_dict = self.convert_xml_list_to_name_id_dict(wbs_in_project)
        self.replicate_content_permissions(project_luid, 'project', wb_dict.values(), 'workbook')
        self.log('Replicating permissions down to datasource')
        ds_dict = self.convert_xml_list_to_name_id_dict(datasources_in_project)
        self.replicate_content_permissions(project_luid, 'project', ds_dict.values(), 'datasource')

    #
    # Delete methods
    #

    # Can take collection or luid_string
    def delete_datasources_by_luid(self, datasource_luid_s):
        datasource_luids = self.to_list(datasource_luid_s)
        for datasource_luid in datasource_luids:
            url = self.build_api_url("datasources/{}".format(datasource_luid))
            self.log("Deleting datasource via  " + url)
            self.send_delete_request(url)

    def delete_projects_by_luid(self, project_luid_s):
        project_luids = self.to_list(project_luid_s)
        for project_luid in project_luids:
            url = self.build_api_url("projects/{}".format(project_luid))
            self.log("Deleting project via  " + url)
            self.send_delete_request(url)

    # Can only delete a site that you have signed into
    def delete_current_site(self):
        url = self.build_api_url("sites/{}".format(self.__site_luid), login=True)
        self.log("Deleting site via " + url)
        self.send_delete_request(url)

    # Can take collection or luid_string
    def delete_workbooks_by_luid(self, wb_luid_s):
        wb_luids = self.to_list(wb_luid_s)
        for wb_luid in wb_luids:
            # Check if workbook_luid exists
            self.query_workbook_by_luid(wb_luid)
            url = self.build_api_url("workbooks/{}".format(wb_luid))
            self.log("Deleting workbook via " + url)
            self.send_delete_request(url)

    # Can take collection or luid_string
    def delete_workbooks_from_user_favorites_by_luid(self, wb_luid_s, user_luid):
        wb_luids = self.to_list(wb_luid_s)
        for wb_luid in wb_luids:
            # Check if workbook_luid exists
            self.query_workbook_by_luid(wb_luid)
            url = self.build_api_url("favorites/{}/workbooks/{}".format(user_luid, wb_luid))
            self.log("Removing workbook from favorites via " + url)
            self.send_delete_request(url)

    def delete_views_from_user_favorites_by_luid(self, view_luid_s, user_luid):
        view_luids = self.to_list(view_luid_s)
        for view_luid in view_luids:
            # Check if workbook_luid exists
            url = self.build_api_url("favorites/{}/views/{}".format(user_luid, view_luid))
            self.log("Removing view from favorites via " + url)
            self.send_delete_request(url)

    # Can take collection or string user_luid string
    def remove_users_from_group_by_luid(self, user_luid_s, group_luid):
        user_luids = self.to_list(user_luid_s)
        for user_luid in user_luids:
            url = self.build_api_url("groups/{}/users/{}".format(user_luid, group_luid))
            self.log("Removing user from group via DELETE on " + url)
            self.send_delete_request(url)

    # Can take collection or single user_luid string
    def remove_users_from_site_by_luid(self, user_luid_s):
        user_luids = self.to_list(user_luid_s)
        for user_luid in user_luids:
            url = self.build_api_url("users/{}".format(user_luid))
            self.log("Removing user from site via DELETE on " + url)
            self.send_delete_request(url)

    # You can throw in a cap_dict { capability_name : capability_mode } 'Allow' or 'Deny' but
    # It ignores and atetempts to delete both Allow and Deny and just ignore any error
    # Default is group because you should be doing all your security by groups instead of individuals
    def delete_permissions_by_luids(self, obj_type, obj_luid_s, luid_s, permissions_dict, luid_type='group'):
        if luid_type not in ['group', 'user']:
            raise InvalidOptionException("luid_type can only be 'group' or 'user'")
        if obj_type not in self.__permissionable_objects:
            raise InvalidOptionException('obj_type must be "workbook","datasource" or "project"')

        luids = self.to_list(luid_s)
        obj_luids = self.to_list(obj_luid_s)

        for luid in luids:
            self.log('Deleting for LUID {}'.format(luid))
            for obj_luid in obj_luids:
                self.log('Deleting for object LUID {}'.format(luid))
                # Check capabiltiies are allowed
                for cap in permissions_dict:
                    if cap not in self.__workbook_caps + self.__datasource_caps + self.__project_caps:
                        raise InvalidOptionException("'{}' is not a capability in the REST API".format(cap))
                    if obj_type == 'datasource' and cap not in self.__datasource_caps:
                        self.log("'{}' is not a valid capability for a datasource".format(cap))
                    if obj_type == 'workbook' and cap not in self.__workbook_caps:
                        self.log("'{}' is not a valid capability for a workbook".format(cap))

                    if permissions_dict.get(cap) == 'Allow':
                        # Delete Allow
                        url = self.build_api_url("{}s/{}/permissions/{}s/{}/{}/Allow".format(obj_type, obj_luid,
                                                                                             luid_type, luid, cap))
                        self.send_delete_request(url)
                    elif permissions_dict.get(cap) == 'Deny':
                        # Delete Deny
                        url = self.build_api_url("{}s/{}/permissions/{}s/{}/{}/Deny".format(obj_type, obj_luid,
                                                                                            luid_type, luid, cap))
                        self.send_delete_request(url)
                    else:
                        self.log('{} set to none, no action'.format(cap))

    # This completely clears out any permissions that an object has. Use a luid_s_to_delete just some permissions
    def delete_all_permissions_by_luids(self, obj_type, obj_luid_s, luid_s_to_delete=None):
        if obj_type not in ['project', 'workbook', 'datasource']:
            raise InvalidOptionException("obj_type must be 'project', 'workbook', or 'datasource'")

        self.log('Deleting all permissions for {} in following: '.format(obj_type))
        if luid_s_to_delete is not None:
            luids_to_delete = self.to_list(luid_s_to_delete)
            self.log('Only deleting permissions for LUIDs {}'.format(luids_to_delete))
        obj_luids = self.to_list(obj_luid_s)
        self.log(obj_luids)
        for obj_luid in obj_luids:
            if obj_type == 'project':
                obj_permissions = self.query_project_permissions(obj_luid)
            elif obj_type == 'workbook':
                obj_permissions = self.query_workbook_permissions_by_luid(obj_luid)
            elif obj_type == 'datasource':
                obj_permissions = self.query_datasource_permissions(obj_luid)
            try:
                cap_list = self.convert_capabilities_xml_into_obj_list(obj_permissions)
                for gcap_obj in cap_list:
                    gcap_luid = gcap_obj.get_luid()
                    # Don't delete if not in the list to delete
                    if luid_s_to_delete is not None:
                        if gcap_luid not in luids_to_delete:
                            continue
                    gcap_obj_type = gcap_obj.get_obj_type()
                    self.log('GranteeCapabilities for {} {}'.format(gcap_obj_type, gcap_luid))
                    capabilities_dict = gcap_obj.get_capabilities_dict()
                    self.delete_permissions_by_luids(obj_type, obj_luids, gcap_luid, capabilities_dict, gcap_obj_type)
            except NoMatchFoundException as e:
                self.log(e)
                self.log('{} {} had no permissions assigned, skipping'.format(obj_type, obj_luid))

    def delete_tags_from_workbook_by_luid(self, wb_luid, tag_s):
        # Check wb_luid
        self.query_workbook_by_luid(wb_luid)
        tags = self.to_list(tag_s)

        deleted_count = 0
        for tag in tags:
            url = self.build_api_url("workbooks/{}/tags/{}".format(wb_luid, tag))
            deleted_count += self.send_delete_request(url)
        return deleted_count
    #
    # Publish methods -- workbook, datasources, file upload
    #

    ''' Publish process can go two way: 
        (1) Initiate File Upload (2) Publish workbook/datasource (less than 64MB) 
        (1) Initiate File Upload (2) Append to File Upload (3) Publish workbook to commit (over 64 MB)
    '''

    def publish_workbook(self, workbook_filename, workbook_name, project_luid, overwrite=False,
                         connection_username=None, connection_password=None, save_credentials=True, show_tabs=True):
        xml = self.publish_content('workbook', workbook_filename, workbook_name, project_luid, overwrite,
                                   connection_username, connection_password, save_credentials, show_tabs=show_tabs)
        workbook = xml.xpath('//t:workbook', namespaces=self.__ns_map)
        return workbook[0].get('id')

    def publish_datasource(self, ds_filename, ds_name, project_luid, overwrite=False, connection_username=None,
                           connection_password=None, save_credentials=True):
        xml = self.publish_content('datasource', ds_filename, ds_name, project_luid, overwrite, connection_username,
                                   connection_password, save_credentials)
        datasource = xml.xpath('//t:datasource', namespaces=self.__ns_map)
        return datasource[0].get('id')

    # Main method for publishing a workbook. Should intelligently decide to chunk up if necessary
    # If a TableauDatasource or TableauWorkbook is passed, will upload from its content
    def publish_content(self, content_type, content_filename, content_name, project_luid, overwrite=False,
                        connection_username=None, connection_password=None, save_credentials=True, show_tabs=False):
        # Single upload limit in MB
        single_upload_limit = 20

        # Must be 'workbook' or 'datasource'
        if content_type not in ['workbook', 'datasource']:
            raise InvalidOptionException("content_type must be 'workbook' or 'datasource'")

        # Check if project_luid exists
        self.query_project_by_luid(project_luid)

        file_extension = None
        final_filename = None
        cleanup_temp_file = False
        # If a packaged file object, save the file locally as a temp for upload, then treated as regular file
        if isinstance(content_filename, TableauPackagedFile):
            content_filename = content_filename.save_new_packaged_file('temp_packaged_file')
            cleanup_temp_file = True

        # If dealing with either of the objects that represent Tableau content
        if isinstance(content_filename, TableauDatasource):
            file_extension = 'tds'
            # Set file size low so it uses single upload instead of chunked
            file_size_mb = 1
            content_file = StringIO(content_filename.get_datasource_xml())
            final_filename = content_name.replace(" ", "") + "." + file_extension
        elif isinstance(content_filename, TableauWorkbook):
            file_extension = 'twb'
            # Set file size low so it uses single upload instead of chunked
            file_size_mb = 1
            content_file = StringIO(content_filename.get_workbook_xml())
            final_filename = content_name.replace(" ", "") + "." + file_extension

        # When uploading directly from disk
        else:
            for ending in ['.twb', '.twbx', '.tde', '.tdsx', '.tds']:
                if content_filename.endswith(ending):
                    file_extension = ending[1:]

                    # Open the file to be uploaded
                    try:
                        content_file = open(content_filename, 'rb')
                        file_size = os.path.getsize(content_filename)
                        file_size_mb = float(file_size) / float(1000000)
                        self.log("File {} is size {} MBs".format(content_filename, file_size_mb))
                        final_filename = content_filename
                    except IOError:
                        print "Error: File '" + content_filename + "' cannot be opened to upload"
                        raise

            if file_extension is None:
                raise InvalidOptionException(
                    "File {} does not have an acceptable extension. Should be .twb,.twbx,.tde,.tdsx,.tds".format(
                        content_filename))

        # Request type is mixed and require a boundary
        boundary_string = self.generate_boundary_string()

        # Create the initial XML portion of the request
        publish_request = "--{}\r\n".format(boundary_string)
        publish_request += 'Content-Disposition: name="request_payload"\r\n'
        publish_request += 'Content-Type: text/xml\r\n\r\n'
        publish_request += '<tsRequest>\n<{} name="{}" '.format(content_type, content_name)
        if show_tabs is not False:
            publish_request += 'showTabs="{}"'.format(str(show_tabs).lower())
        publish_request += '>\r\n'
        if connection_username is not None and connection_password is not None:
            publish_request += '<connectionCredentials name="{}" password="{}" embed="{}" />\r\n'.format(
                connection_username, connection_password, str(save_credentials).lower())
        publish_request += '<project id="{}" />\r\n'.format(project_luid)
        publish_request += "</{}></tsRequest>\r\n".format(content_type)
        publish_request += "--{}".format(boundary_string)

        # Upload as single if less than file_size_limit MB
        if file_size_mb <= single_upload_limit:
            # If part of a single upload, this if the next portion
            self.log("Less than {} MB, uploading as a single call".format(str(single_upload_limit)))
            publish_request += '\r\n'
            publish_request += 'Content-Disposition: name="tableau_{}"; filename="{}"\r\n'.format(
                content_type, final_filename)
            publish_request += 'Content-Type: application/octet-stream\r\n\r\n'

            # Content needs to be read unencoded from the file
            content = content_file.read()

            # If twb, create a TableauWorkbook object and check for any published data sources
            if file_extension == 'twb':
                if isinstance(content_filename, TableauWorkbook):
                    wb_obj = content_filename
                else:
                    wb_obj = TableauWorkbook(content)
                for ds in wb_obj.get_datasources().values():
                    if ds.ds_name == 'Parameters':  # ignores the parameter datasource that cannot be published
                        continue
                    if ds.connection.is_published_datasource():
                        pub_ds_name = ds.get_datasource_name()
                        self.log("Workbook contains published data source named {}".format(pub_ds_name))
                        try:
                            self.query_datasource_by_name(pub_ds_name)
                        except NoMatchFoundException as e:
                            e_txt = "Required published data source {} does not exist on this site".format(pub_ds_name)
                            raise NoMatchFoundException(e_txt)
            # Add to string as regular binary, no encoding
            publish_request += content

            publish_request += "\r\n--{}--".format(boundary_string)
            url = self.build_api_url("{}s").format(content_type) + "?overwrite={}".format(str(overwrite).lower())
            content_file.close()
            if cleanup_temp_file is True:
                os.remove(final_filename)
            return self.send_publish_request(url, publish_request, boundary_string)
        # Break up into chunks for upload
        else:
            self.log("Greater than 10 MB, uploading in chunks")
            upload_session_id = self.initiate_file_upload()

            for piece in self.__read_file_in_chunks(content_file):
                self.log("Appending chunk to upload session {}".format(upload_session_id))
                self.append_to_file_upload(upload_session_id, piece, final_filename)

            url = self.build_api_url("{}s").format(content_type) + "?uploadSessionId={}".format(
                upload_session_id) + "&{}Type={}".format(content_type, file_extension) + "&overwrite={}".format(
                str(overwrite).lower())
            publish_request += "--"  # Need to finish off the last boundary
            self.log("Finishing the upload with a publish request")
            content_file.close()
            if cleanup_temp_file is True:
                os.remove(final_filename)
            return self.send_publish_request(url, publish_request, boundary_string)

    def initiate_file_upload(self):
        url = self.build_api_url("fileUploads")
        xml = self.send_post_request(url)
        file_upload = xml.xpath('//t:fileUpload', namespaces=self.__ns_map)
        return file_upload[0].get("uploadSessionId")

    # Uploads a check to an already started session
    def append_to_file_upload(self, upload_session_id, content, filename):
        boundary_string = self.generate_boundary_string()
        publish_request = "--{}\r\n".format(boundary_string)
        publish_request += 'Content-Disposition: name="request_payload"\r\n'
        publish_request += 'Content-Type: text/xml\r\n\r\n'
        publish_request += "--{}\r\n".format(boundary_string)
        publish_request += 'Content-Disposition: name="tableau_file"; filename="{}"\r\n'.format(
            filename)
        publish_request += 'Content-Type: application/octet-stream\r\n\r\n'

        publish_request += content

        publish_request += "\r\n--{}--".format(boundary_string)
        url = self.build_api_url("fileUploads/{}".format(upload_session_id))
        self.send_append_request(url, publish_request, boundary_string)


# Handles all of the actual HTTP calling
class RestXmlRequest:
    def __init__(self, url, token=None, logger=None):
        self.__defined_response_types = ('xml', 'png', 'binary')
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
        self.__publish = None
        self.__boundary_string = None
        self.__publish_content = None
        self.__http_verb = None
        self.__response_type = None
        self.__last_response_content_type = None
        self.__luid_pattern = r"[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*"

        try:
            self.set_http_verb('get')
            self.set_response_type('xml')
        except:
            raise

    def log(self, l):
        if self.__logger is not None:
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

    def get_last_response_content_type(self):
        return self.__last_response_content_type

    def get_response(self):
        if self.__response_type == 'xml' and self.__xml_object is not None:
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
            param_separator = '?'
            # If already a parameter, just append
            if '?' in url:
                param_separator = '&'
            url = url + "{}pageNumber={}".format(param_separator, str(page_number))
        self.__last_url_request = url

        # Logic to create correct request
        opener = urllib2.build_opener(urllib2.HTTPHandler)
        request = urllib2.Request(url)
        if self.__http_verb == 'delete':
            request.get_method = lambda: 'DELETE'

        if self.__http_verb == 'put' or self.__http_verb == 'post':
            if self.__publish_content is not None:
                request.add_data(self.__publish_content)
            elif self.__xml_request is not None:
                request.add_data(self.__xml_request.encode("utf8"))
            else:
                request.add_data("")
        if self.__http_verb == 'put':
            request.get_method = lambda: 'PUT'
        if self.__token:  # altered the condition to avoid passing in header during authentication
            request.add_header('X-tableau-auth', self.__token)
        if self.__publish is True:
            request.add_header('Content-Type', 'multipart/mixed; boundary={}'.format(self.__boundary_string))

        # Need to handle binary return for image somehow
        try:
            self.log("Making REST request to Tableau Server using {}".format(self.__http_verb))
            self.log("Request URI: {}".format(url))
            if self.__xml_request is not None:
                self.log("Request XML:\n{}".format(self.__xml_request))
            response = opener.open(request)
            self.__raw_response = response.read()  # Leave the UTF8 decoding to lxml
            self.__last_response_content_type = response.info().getheader('Content-Type')
            self.log("Content type from headers: {}".format(self.__last_response_content_type))
            if self.__response_type == 'xml':
                self.log("Raw Response:\n{}".format(str(self.__raw_response)))
            return True
        except urllib2.HTTPError as e:
            # No recoverying from a 500
            if e.code >= 500:
                raise
            # REST API returns 400 type errors that can be recovered from, so handle them
            raw_error_response = e.fp.read()
            self.log("Received a {} error, here was response:".format(str(e.code)))
            self.log(raw_error_response.decode('utf8'))

            utf8_parser = etree.XMLParser(encoding='utf-8')
            xml = etree.parse(StringIO(raw_error_response), parser=utf8_parser)
            tableau_error = xml.xpath('//t:error', namespaces=self.__ns_map)
            error_code = tableau_error[0].get('code')
            tableau_detail = xml.xpath('//t:detail', namespaces=self.__ns_map)
            detail_text = tableau_detail[0].text
            detail_luid_match_obj = re.search(self.__luid_pattern, detail_text)
            if detail_luid_match_obj:
                detail_luid = detail_luid_match_obj.group(0)
            else:
                detail_luid = False
            self.log('Tableau REST API error code is: {}'.format(error_code))
            # Everything that is not 400 can potentially be recovered from
            if e.code in [401, 402, 403, 404, 405, 409]:
                # If 'not exists' for a delete, recover and log
                if self.__http_verb == 'delete':
                    self.log('Delete action attempted on non-exists, keep going')
                if e.code == 409:
                    self.log('HTTP 409 error, most likely an already exists')
                raise RecoverableHTTPException(e.code, error_code, detail_luid)
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

                # page_number = int(pagination.get('pageNumber'))
                page_size = int(pagination.get('pageSize'))
                total_available = int(pagination.get('totalAvailable'))
                total_pages = int(math.ceil(float(total_available) / float(page_size)))
                combined_xml_string = '<tsResponse xmlns="http://tableausoftware.com/api" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://tableausoftware.com/api http://tableausoftware.com/api/ts-api-2.0.xsd">'
                full_xml_obj = None
                for obj in xml.getroot():
                    if obj.tag != 'pagination':
                        full_xml_obj = obj

                # Convert the internal part of the XML response that is not Pagination back into xml text
                # Then convert innermost part into a new XML object
                new_xml_text_lines = etree.tostring(full_xml_obj).split("\n")
                # First and last tags should be removed (spit back with namespace tags that are included via start text
                a = new_xml_text_lines[1:]
                xml_text_lines = a[:-2]

                if total_pages > 1:
                    for i in xrange(2, total_pages + 1):

                        self.__make_request(i)  # Get next page
                        xml = etree.parse(StringIO(self.__raw_response), parser=utf8_parser)
                        for obj in xml.getroot():
                            if obj.tag != 'pagination':
                                full_xml_obj = obj
                        new_xml_text_lines = etree.tostring(full_xml_obj).split("\n")
                        a = new_xml_text_lines[1:]  # Chop first tag
                        xml_text_lines.extend(a[:-2])  # Add the newly brought in lines to the overall text lines

                for line in xml_text_lines:
                    combined_xml_string = combined_xml_string + line
                combined_xml_string += "</tsResponse>"

                self.__xml_object = etree.parse(StringIO(combined_xml_string), parser=utf8_parser)
                return True
        elif self.__response_type in ['binary', 'png']:
            self.log('Binary response (binary or png) rather than XML')
            return True


# Represents the GranteeCapabilities from any given
class GranteeCapabilities:
    def __init__(self, obj_type, luid):
        if obj_type not in ['group', 'user']:
            raise InvalidOptionException('GranteeCapabilites type must be "group" or "user"')
        self.obj_type = obj_type
        self.luid = luid
        self.__capabilities = {
            'AddComment': None,
            'ChangeHierarchy': None,
            'ChangePermissions': None,
            'Connect': None,
            'Delete': None,
            'ExportData': None,
            'ExportImage': None,
            'ExportXml': None,
            'Filter': None,
            'ProjectLeader': None,
            'Read': None,
            'ShareView': None,
            'ViewComments': None,
            'ViewUnderlyingData': None,
            'WebAuthoring': None,
            'Write': None
        }
        self.__allowable_modes = ['Allow', 'Deny', None]
        self.__server_to_rest_capability_map = {
            'Add Comment': 'AddComment',
            'Move': 'ChangeHierarchy',
            'Set Permissions': 'ChangePermissions',
            'Connect': 'Connect',
            'Delete': 'Delete',
            'View Summary Data': 'ExportData',
            'Export Image': 'ExportImage',
            'Download': 'ExportXml',
            'Filter': 'Filter',
            'Project Leader': 'ProjectLeader',
            'View': 'Read',
            'Share Customized': 'ShareView',
            'View Comments': 'ViewComments',
            'View Underlying Data': 'ViewUnderlyingData',
            'Web Edit': 'WebAuthoring',
            'Save': 'Write'
            }

    def set_capability(self, capability_name, mode):
        if mode not in self.__allowable_modes:
            raise InvalidOptionException('"{}" is not an allowable mode'.format(mode))
        if capability_name not in self.__capabilities:
            # If it's the Tableau UI naming, translate it over
            if capability_name in self.__server_to_rest_capability_map:
                capability_name = self.__server_to_rest_capability_map[capability_name]
            else:
                raise InvalidOptionException('"{}" is not a capability in REST API or Server'.format(capability_name))
        self.__capabilities[capability_name] = mode

    def set_capability_to_unspecified(self, capability_name):
        if capability_name not in self.__capabilities:
            # If it's the Tableau UI naming, translate it over
            if capability_name in self.__server_to_rest_capability_map:
                capability_name = self.__server_to_rest_capability_map[capability_name]
            else:
                raise InvalidOptionException('"{}" is not a capability in REST API or Server'.format(capability_name))
        self.__capabilities[capability_name] = None

    def get_capabilities_dict(self):
        return self.__capabilities

    def get_obj_type(self):
        return self.obj_type

    def get_luid(self):
        return self.luid

    def set_obj_type(self, obj_type):
        if obj_type.lower() in ['group', 'user']:
            self.obj_type = obj_type.lower()
        else:
            raise InvalidOptionException('obj_type can only be "group" or "user"')

    def set_luid(self, new_luid):
        self.luid = new_luid

    def set_all_to_deny(self):
        for cap in self.__capabilities:
            self.__capabilities[cap] = 'Deny'

    def set_all_to_allow(self):
        for cap in self.__capabilities:
            self.__capabilities[cap] = 'Allow'


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


# Represents a TWBX or TDSX and allows manipulation of the XML objects inside via their related object
class TableauPackagedFile:
    def __init__(self, zip_file_obj, logger_obj=None):
        self.__logger = logger_obj
        self.zf = zipfile.ZipFile(zip_file_obj)
        self.xml_name = None
        self.type = None  # either 'twbx' or 'tdsx'
        self.tableau_object = None
        self.other_files = []
        for name in self.zf.namelist():
            # Ignore anything in the subdirectories
            if name.find('/') == -1:
                if name.endswith('.tds'):
                    self.type = 'tdsx'
                    self.xml_name = name
                    tds_file_obj = self.zf.open(self.xml_name)
                    self.tableau_object = TableauDatasource(tds_file_obj.read(), self.__logger)
                elif name.endswith('.twb'):
                    self.type = 'twbx'
                    self.xml_name = name
                    twb_file_obj = self.zf.open(self.xml_name)
                    self.tableau_object = TableauWorkbook(twb_file_obj.read(), self.__logger)

            else:
                self.other_files.append(name)

    def log(self, l):
        if self.__logger is not None:
            self.__logger.log(l)

    def get_type(self):
        return self.type

    def get_tableau_object(self):
        return self.tableau_object

    # Appropriate extension added if needed
    def save_new_packaged_file(self, new_filename_no_extension):
        new_filename = new_filename_no_extension.split('.') # simple algorithm to kill extension

        # Save the object down
        if self.type == 'twbx':
            save_filename = new_filename[0] + '.twbx'
            new_zf = zipfile.ZipFile(save_filename, 'w')
            self.log('Creating temporary XML file {}'.format(self.xml_name))
            self.tableau_object.save_workbook_xml(self.xml_name)
            new_zf.write(self.xml_name)
            os.remove(self.xml_name)
        elif self.type == 'tdsx':
            save_filename = new_filename[0] + '.tdsx'
            new_zf = zipfile.ZipFile(save_filename, 'w')
            self.log('Creating temporary XML file {}'.format(self.xml_name))
            self.tableau_object.save_datasource_xml(self.xml_name)
            new_zf.write(self.xml_name)
            os.remove(self.xml_name)
            self.log('Removed file {}'.format(save_filename))

        temp_directories_to_remove = {}
        for filename in self.other_files:
            self.log('Extracting file {} temporarily'.format(filename))
            self.zf.extract(filename)
            new_zf.write(filename)
            os.remove(filename)
            self.log('Removed file {}'.format(filename))
            lowest_level = filename.split('/')
            temp_directories_to_remove[lowest_level[0]] = True

        # Cleanup all the temporary directories
        for directory in temp_directories_to_remove:
            shutil.rmtree(directory)
        new_zf.close()
        self.zf.close()

        # Return the filename so it can be opened from disk by other objects
        return save_filename


# Meant to represent a TDS file, does not handle the file opening
class TableauDatasource:
    def __init__(self, datasource_string, logger_obj=None):
        self.__logger = logger_obj
        self.ds = StringIO(datasource_string)
        self.start_xml = ""
        self.end_xml = ""
        self.ds_name = None
        self.connection = None

        if self.__logger is not None:
            self.enable_logging(self.__logger)

        # Find connection line and build TableauConnection object
        start_flag = True
        for line in self.ds:
            # Grab the caption if coming from
            if line.find('<datasource ') != -1:
                # Complete the tag so XML can be parsed
                ds_tag = line + '</datasource>'
                utf8_parser = etree.XMLParser(encoding='utf-8')
                xml = etree.parse(StringIO(ds_tag), parser=utf8_parser)
                xml_obj = xml.getroot()
                if xml_obj.get("caption"):
                    self.ds_name = xml_obj.attrib["caption"]
                elif xml_obj.get("name"):
                    self.ds_name = xml_obj.attrib['name']
                if start_flag is True:
                    self.start_xml += line
                elif start_flag is False:
                    self.end_xml += line
            elif line.find('<connection ') != -1 and start_flag is True:
                self.connection = TableauConnection(line)
                self.log("This is the connection line:")
                self.log(line)
                start_flag = False
                continue
            else:
                if start_flag is True:
                    self.start_xml += line
                elif start_flag is False:
                    self.end_xml += line

    def enable_logging(self, logger_obj):
        if isinstance(logger_obj, Logger):
            self.__logger = logger_obj

    def log(self, l):
        if self.__logger is not None:
            self.__logger.log(l)

    def get_datasource_name(self):
        return self.ds_name

    def get_datasource_xml(self):
        xml = self.start_xml
        # Parameters datasource section does not have a connection tag
        if self.connection is not None:
            xml += self.connection.get_xml_string()
        xml += self.end_xml
        return xml

    def save_datasource_xml(self, filename):
        try:
            lh = open(filename, 'wb')
            lh.write(self.get_datasource_xml())
            lh.close()
        except IOError:
            print "Error: File '" + filename + "' cannot be opened to write to"
            raise


class TableauWorkbook:
    def __init__(self, wb_string, logger_obj=None):
        self.__logger = logger_obj
        self.wb_string = wb_string
        self.wb = StringIO(self.wb_string)
        self.start_xml = ""
        self.end_xml = ""
        self.datasources = {}
        start_flag = True
        ds_flag = False
        current_ds = ""

        if self.__logger is not None:
            self.enable_logging(self.__logger)

        for line in self.wb:
            # Start parsing the datasources
            if start_flag is True and ds_flag is False:
                self.start_xml += line
            if start_flag is False and ds_flag is False:
                self.end_xml += line
            if ds_flag is True:
                current_ds += line
                # Break and load the datasource
                if line.find("</datasource>") != -1:
                    self.log("Building TableauDatasource object")
                    ds_obj = TableauDatasource(current_ds, logger_obj=self.__logger)
                    self.datasources[ds_obj.get_datasource_name()] = ds_obj
                    current_ds = ""
            if line.find("<datasources") != -1 and start_flag is True:
                start_flag = False
                ds_flag = True

            if line.find("</datasources>") != -1 and ds_flag is True:
                self.end_xml += line
                ds_flag = False

    def enable_logging(self, logger_obj):
        if isinstance(logger_obj, Logger):
            self.__logger = logger_obj

    def log(self, l):
        if self.__logger is not None:
            self.__logger.log(l)

    def get_datasources(self):
        return self.datasources

    def get_workbook_xml(self):
        xml = self.start_xml
        for ds in self.datasources:
            self.log('Adding in XML from datasource {}'.format(ds))
            xml += self.datasources.get(ds).get_datasource_xml()
        xml += self.end_xml
        return xml

    def save_workbook_xml(self, filename):
        try:
            lh = open(filename, 'wb')
            lh.write(self.get_workbook_xml())
            lh.close()
        except IOError:
            print "Error: File '" + filename + "' cannot be opened to write to"
            raise

# Represents the actual Connection tag of a given datasource
class TableauConnection:
    def __init__(self, connection_line, logger_obj=None):
        self.__logger = logger_obj
        # Building from a <connection> tag
        self.xml_obj = None

        if self.__logger is not None:
            self.enable_logging(self.__logger)

        if connection_line.find("<connection "):
            self.log('Looking at: {}'.format(connection_line))
            # Add ending tag for XML parsing
            connection_line += "</connection>"
            utf8_parser = etree.XMLParser(encoding='utf-8')
            xml = etree.parse(StringIO(connection_line), parser=utf8_parser)
            self.xml_obj = xml.getroot()
            # xml = etree.fromstring(connection_line)
        else:
            raise InvalidOptionException("Must create a TableauConnection from a Connection line")

    def enable_logging(self, logger_obj):
        if isinstance(logger_obj, Logger):
            self.__logger = logger_obj

    def log(self, l):
        if self.__logger is not None:
            self.__logger.log(l)

    def set_dbname(self, new_db_name):
        if self.xml_obj.attrib["dbname"] is not None:
            self.xml_obj.attrib["dbname"] = new_db_name

    def get_dbname(self):
        return self.xml_obj.attrib["dbname"]

    def set_server(self, new_server):
        if self.xml_obj.attrib["server"] is not None:
            self.xml_obj.attrib["server"] = new_server

    def get_server(self):
        return self.xml_obj.attrib["server"]

    def set_username(self, new_username):
        if self.xml_obj.attrib["username"] is not None:
            self.xml_obj.attrib["username"] = new_username

    def set_port(self, new_port):
        if self.xml_obj.attrib["port"] is not None:
            self.xml_obj.attrib["port"] = new_port

    def get_port(self):
        return self.xml_obj.attrib["port"]

    def get_connection_type(self):
        return self.xml_obj.attrib['class']

    def get_xml_string(self):
        xml_with_ending_tag = etree.tostring(self.xml_obj)
        # Slice off the extra connection ending tag
        return xml_with_ending_tag[0:xml_with_ending_tag.find('</connection>')]

    def is_published_datasource(self):
        if self.xml_obj.attrib["class"] == 'sqlproxy':
            return True
        else:
            return False

    def is_windows_auth(self):
        if self.xml_obj.attrib["authentication"] is not None:
            if self.xml_obj.attrib["authentication"] == 'sspi':
                return True
            else:
                return False

# Exceptions
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


class RecoverableHTTPException(Exception):
    def __init__(self, http_code, tableau_error_code, luid):
        self.http_code = http_code
        self.tableau_error_code = tableau_error_code
        self.luid = luid


class MultipleMatchesFound(Exception):
    def __init__(self, count):
        self.msg = 'Found {} matches for the request, something has the same name'.format(str(count))
