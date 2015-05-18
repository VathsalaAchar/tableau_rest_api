import tableau_rest_api
import urllib2
import time

# User your 
username = ''
password = ''
tab_srv = rest_api.TableauRestApi('http://127.0.0.1', username, password, 'default')
logger = rest_api.Logger('rest_test.log')
tab_srv.enable_logging(logger)

tab_srv.signin()

new_site_name = 'Test Site'
new_site_content_url = 'ts'
try:
    # Determine if site exists with current name. Delete if it does.
    # Then create new site with the same name and contentUrl
    try:
        delete_login_content_url = tab_srv.query_site_content_url_by_site_name('Programmatic Site 2')
        print 'Received content_url to delete ' + delete_login_content_url
        tab_srv_2 = rest_api.TableauRestApi('http://127.0.0.1', username, password, delete_login_content_url)
        tab_srv_2.enable_logging(logger)
        tab_srv_2.signin()
        print 'Signed in successfully to ' + delete_login_content_url

        print 'Querying the current site'
        site_xml = tab_srv_2.query_current_site()
        print site_xml

        print 'Attempting to delete current site'
        tab_srv_2.delete_current_site()
        print "Deleted site " + new_site_name
    except rest_api.NoMatchFoundException as e:
        print e.msg
        print "Cannot delete site that does not exist"
    except Exception as e:
        raise

    try:
        # Create the new site
        print 'Now going into the create site'
        tab_srv.log('Logging with the log function')
        new_site_id = tab_srv.create_site(new_site_name, new_site_content_url)
        print 'Created new site ' + new_site_id
    except rest_api.AlreadyExistsException as e:
        print e.msg
        print "Cannot create new site, exiting"
        exit()
    except Exception as e:
        raise

    # Once we've created the site, we need to sign into it to do anything else
    tab_srv_3 = rest_api.TableauRestApi('http://127.0.0.1', username, password, new_site_content_url)
    tab_srv_3.enable_logging(logger)
    try:
        tab_srv_3.signin()
        # Add groups and users to the site
        print 'Signed in successfully to ' + new_site_content_url

        # Update the site name
        print 'Updating site name'
        tab_srv_3.update_current_site('Programmatic Site 2')

        projects_to_create = ['Sandbox', 'Approved Datasources', 'Production']
        for project in projects_to_create:
            print "Creating Project '" + project + "'"
            new_proj_luid = tab_srv_3.create_project(project)
        
        groups_to_create = ['Publishers', 'Site Admins', 'Super Admins', 'Sales', 'Marketing', 'IT', 'VPs']
        for group in groups_to_create:
            print "Creating Group '" + group + "'"
            new_group_luid = tab_srv_3.create_group(group)
            print "updating the group name"
            time.sleep(1)
            tab_srv_3.update_group_by_luid(new_group_luid, group + ' (Awesome)')
        
        print "Sleeping 1 second for group creation to finish"
        # It does take a second for the indexing to update, so if you've made a lot of changes, pause for 1 sec
        time.sleep(1)

        print "Get all the groups"
        groups_on_site = tab_srv_3.query_groups()

        # Assign permissions on each project, for each group

        print "Converting the groups to a dict"
        # Convert the list to a dict {name : luid}
        groups_dict = tab_srv_3.convert_xml_list_to_name_id_dict(groups_on_site)
        print groups_dict

        sandbox_luid = tab_srv_3.query_project_luid_by_name('Sandbox')

        # Change the Sandbox name
        tab_srv_3.update_project_by_name('Sandbox', 'Protected Sandbox', 'This is only for important people')

        group_luids = []
        for group in groups_dict:
            group_luids.append(groups_dict[group])
        sandbox_permissions = {'ChangePermissions': 'Allow', 'Connect': 'Allow', 'Delete': 'Deny',
                               'ExportXml': 'Deny', 'Read': 'Allow', 'Write': 'Deny', 'ExportImage': 'Allow',
                               'ExportData': 'Allow', 'WebAuthoring': 'Allow', 'ViewComments': 'Allow',
                               'ShareView': 'Allow', 'AddComment': 'Allow', 'Filter': 'Allow',
                               'ChangeHierarchy': 'Allow'}
        print 'Adding permissions for Sandbox for all groups'
        #tab_srv_3.add_permissions_by_luids('project', sandbox_luid, group_luids, sandbox_permissions, 'group')

        tab_srv_3.update_permissions_by_luids('project', sandbox_luid, group_luids, sandbox_permissions, 'group')

        # Create some fake users to assign to groups
        new_user_luids = []
        for i in range(1, 6):
            username = "user" + str(i)
            full_name = "User {}".format(str(i)) 
            print "Creating User '{}' named '{}'".format(username, full_name)
            new_user_luid = tab_srv_3.add_user(username, full_name, 'Interactor', 'password', username + '@nowhere.com')
            print "New User LUID : {}".format(new_user_luid)
            new_user_luids.append(new_user_luid)
        
        for group in groups_dict:
            print "Adding users to group {}".format(group)
            tab_srv_3.add_users_to_group_by_luid(new_user_luids, groups_dict.get(group))

        user_1_luid = tab_srv_3.query_user_luid_by_username('user1')
        print " User 1 luid: {}".format(user_1_luid)
        # Teardown users
        # Delete all of the users that were just created
        # tab_srv_3.remove_users_from_site_by_luid(new_user_luids)

        try:
            project_luid = tab_srv_3.query_project_luid_by_name('Protected Sandbox')
            print "Sandbox project luid: " + project_luid

            print "Querying project permissions"
            project_permissions = tab_srv_3.query_project_permissions_by_luid(project_luid)
            print project_permissions

            # Publish a datasource to the Sandbox project
            print 'Publishing datasource to Protected Sandbox'
            new_ds_luid = tab_srv_3.publish_datasource('Flights Data.tde', 'Flights Data', project_luid, True)
            print 'Publishing as {}'.format(new_ds_luid)
            print "Query the datasource"
            ds_xml = tab_srv_3.query_datasource_by_luid(new_ds_luid)

            print "Querying datasource permissions"
            ds_perms = tab_srv_3.query_datasource_permissions_by_luid(new_ds_luid)
            print ds_perms

            print "Querying All datasources"
            datasources = tab_srv_3.query_datasources()

            print 'Publishing workbook to PRoduction'
            production_luid = tab_srv_3.query_project_luid_by_name('Production')
            new_wb_luid = tab_srv_3.publish_workbook('Flights Data.twbx', 'Flights Workbooks', production_luid, True)
            print 'Moving workbook to Sandbox'
            tab_srv_3.update_workbook_by_luid(new_wb_luid, sandbox_luid, False, True)
            print "querying workbook"
            wb_xml = tab_srv_3.query_workbook_by_luid(new_wb_luid)

            print "assign permissions to workbook"
            tab_srv_3.add_permissions_by_luids('workbook', new_wb_luid, group_luids, sandbox_permissions, 'group')

            print "Assigning permission to datasource"
            try:
                tab_srv_3.add_permissions_by_luids('datasource', new_ds_luid, group_luids, sandbox_permissions, 'group')
            except rest_api.InvalidOptionException as e:
                print e.msg
            # print "Deleting the published DS"
            # tab_srv_3.delete_datasources_by_luid(new_ds_luid)

            print "Moving datasource to production"
            tab_srv_3.update_datasource_by_luid(new_ds_luid, 'Flites Datums', production_luid)

            print "Query workbook connections"
            wb_connections = tab_srv_3.query_workbook_connections_by_luid(new_wb_luid)
            print wb_connections

            print "Querying workbook permissions"
            wb_permissions = tab_srv_3.query_workbook_permissions_by_luid(new_wb_luid)
            print wb_permissions

            print "Adding permissions to workbook"
            tab_srv_3.add_permissions_by_luids('workbook', new_wb_luid, group_luids, sandbox_permissions, 'group')

            # print "Deleting Permissions from workbook"
            # tab_srv_3.delete_permissions_by_luids('workbook', new_wb_luid, group_luids, sandbox_permissions, 'group')

            # print "Deleting Permissions from project"
            # tab_srv_3.delete_permissions_by_luids('project', project_luid, group_luids, sandbox_permissions, 'group')

            print "Querying workbook views"
            wb_views = tab_srv_3.query_workbook_views_by_luid(new_wb_luid, True)
            print wb_views

            wb_views_dict = tab_srv_3.convert_xml_list_to_name_id_dict(wb_views)

            print wb_views_dict

            for wb_view in wb_views_dict:
                print "Adding {} to favorites for User 1".format(wb_view)
                tab_srv_3.add_view_to_user_favorites_by_luid('Fav: {}'.format(wb_view), wb_views_dict.get(wb_view), tab_srv_3.query_user_luid_by_username('user1'))

            for wb_view in wb_views_dict:
                print "Deleting {} to favorites for User 1".format(wb_view)
                tab_srv_3.delete_views_from_user_favorites_by_luid(wb_views_dict.get(wb_view), tab_srv_3.query_user_luid_by_username('user1'))

            # Save workbook preview image
            print "Saving workbook preview image"
            tab_srv_3.save_workbook_preview_image(new_wb_luid, 'Workbook preview')

            # Saving view as file
            for wb_view in wb_views_dict:
                print "Saving a png for {}".format(wb_view)
                tab_srv_3.save_workbook_view_preview_image_by_luid(new_wb_luid, wb_views_dict.get(wb_view), '{}_preview'.format(wb_view))

            print "Saving workbook file"
            tab_srv_3.download_workbook_by_luid(new_wb_luid, 'saved workbook')

            print "Saving Datasource"
            tab_srv_3.download_datasource_by_luid(new_ds_luid, 'saved_datasource')
            print 'Adding tags to workbook'
            tab_srv_3.add_tags_to_workbook_by_luid(new_wb_luid, ['workbooks', 'flights', 'cool'])

            print 'Deleting a tag from workbook'
            tab_srv_3.delete_tags_from_workbook_by_luid(new_wb_luid, 'flights')

            print "Add workbook to favorites for bhowell"
            tab_srv_3.add_workbook_to_user_favorites_by_luid('My favorite workbook', new_wb_luid, tab_srv_3.query_user_luid_by_username('user1'))

            print "Deleting workbook from favorites for bhowell"
            tab_srv_3.delete_workbooks_from_user_favorites_by_luid(new_wb_luid, tab_srv_3.query_user_luid_by_username('user1'))

            print "Publishing a TWB"
            twb_luid = tab_srv_3.publish_workbook('TWB to Publish.twb', 'TWB Publish Test', project_luid)

            print "Downloading TWB"
            tab_srv_3.download_workbook_by_luid(twb_luid, 'TWB Save')

            print "Publishing a TDS"
            tds_luid = tab_srv_3.publish_datasource('TDS to Publish SS.tds', 'SS TDS', project_luid)

            # print "Publishing TDS with credentials"
            # tds_cred_luid = tab_srv_3.publish_datasource('TDS with Credentials.tds', 'TDS w Creds', project_luid, True, db_username, db_password)

            # print "Update Datasource connection"
            # tab_srv_3.update_datasource_connection_by_luid(tds_cred_luid, 'localhost', '5432', db_username, db_password)

            print "Saving TDS"
            tab_srv_3.download_datasource_by_luid(tds_luid, 'TDS Save')

            print "Publishing a TDSX"
            tab_srv_3.publish_datasource('TDSX to Publish.tdsx', 'TDSX Publish Test', project_luid)

        except rest_api.NoMatchFoundException as e:
                print e.msg
        except:
            raise

    except rest_api.NoMatchFoundException as e:
        print e.msg
    except:
        raise
    
except urllib2.HTTPError as e:
    print e.code
    print e.msg
    print e.hdrs
    print e.fp
except Exception as e:
   raise
