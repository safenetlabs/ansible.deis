#!/usr/bin/python
import os
import urllib


def main():

    module = AnsibleModule(
        argument_spec=dict(
            action=dict(type='str', required=False),
            username=dict(type='str', required=False),
            password=dict(type='str', required=False),
            email=dict(type='str', required=False),
            domain=dict(type='str', required=False),
            app=dict(type='str', required=False),
            app_name_for_domain=dict(type='str', required=False),
            config_vars=dict(type='str', required=False),
            app_ver=dict(type='str', required=False),
            scale=dict(type='str', required=False),
            source=dict(type='str', required=False),
        )
    )

    action = module.params['action']
    username = module.params['username']
    password = module.params['password']
    email = module.params['email']
    domain = module.params['domain']
    app_name_for_domain = module.params['app_name_for_domain']
    app = module.params['app']
    config_vars = module.params['config_vars']
    app_ver = module.params['app_ver']
    scale = module.params['scale']
    source = module.params['source']
    deis = "/opt/bin/deis"

    if action == '':
        module.fail_json(msg="No action provided")

    elif action == 'install_deis':
        if os.path.exists('/opt/bin/deis'):
            module.exit_json(changed=False, msg="DEIS already installed")
        else:
            os.chdir('/opt/bin/')
            urllib.urlretrieve('http://deis.io/deis-cli/install.sh', 'install.sh')
            cmd = 'sh install.sh'
            rc, resp, err = module.run_command(cmd)
            os.remove('/opt/bin/install.sh')
            if rc == 0:
                module.exit_json(changed=True, msg="DEIS installed successfully")
            else:
                module.exit_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while installing DEIS")

    elif action == 'register':
        if username is None or password is None or email is None:
            module.fail_json(msg="Username, password or email not provided")
        else:
            full_action = "auth:register deis." + domain
            cmd = deis + " " + full_action + " --username=" + username + " --password=" + password + " --email=" + email
            rc, resp, err = module.run_command(cmd)

            if rc == 0:
                module.exit_json(changed=True, msg="User registered Successfully")

            if "This field must be unique" in err:
                module.exit_json(changed=False, msg="User already exists")
            else:
                module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while regisetring user")

    elif action == 'login':
        if username is None or password is None:
            module.fail_json(msg="Username or/and password not provided")
        else:
            is_logged_in = deis + " whoami"
            rc, resp, err = module.run_command(is_logged_in)
            if rc == 1:
                full_action = "auth:login deis." + domain
                cmd = deis + " " + full_action + " --username=" + username + " --password=" + password
                rc, resp, err = module.run_command(cmd)

                if rc == 0:
                    module.exit_json(changed=True, msg="Login Successful", stdout=resp)
                else:
                    module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while logging in")
            else:
                    module.exit_json(changed=False, msg="Already logged in")

    elif action == 'create':
        if app is None:
            module.fail_json(msg="App name not provided")
        else:
            cmd = deis + " apps:create --no-remote " + app
            rc, resp, err = module.run_command(cmd)

            if rc == 0:
                module.exit_json(changed=True, msg=app + " created successfully", stdout=resp)

            if "This field must be unique" in err:
                module.exit_json(changed=False, msg=app + " already exists")
            else:
                module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while creating " + app)

    elif action == 'configure':
        if app is None or config_vars is None:
            module.fail_json(msg="App Name or/and config variables not provided")
        else:
            list_cmd = deis + " config:list -a " + app
            rc, resp, err = module.run_command(list_cmd)
            resp = resp[resp.index('\n')+1:]

            input_vars_list = config_vars.split('\\\n')
            input_vars_dict = dict(var.split('=', 1) for var in input_vars_list)

            deis_vars_list = resp.splitlines()
            deis_vars_dict = dict(var.split() for var in deis_vars_list)

            set_cmd = deis + " config:set "
            unset_cmd = deis + " config:unset "
            set_changes = False
            unset_changes = False
            set_rc = 0
            unset_rc = 0

            for key, val in input_vars_dict.iteritems():
                if key not in deis_vars_dict or deis_vars_dict[key] != val.strip():
                    if key == "SSH_KEY" and key in deis_vars_dict:
                        continue
                    set_cmd += key + '=' + val + ' '
                    set_changes = True

            for key, val in deis_vars_dict.iteritems():
                if key not in input_vars_dict:
                    unset_cmd += key + ' '
                    unset_changes = True

            if set_changes:
                set_cmd += '-a ' + app
                set_rc, resp, err = module.run_command(set_cmd)
                if set_rc != 0:
                   module.fail_json(changed=False, rc=rc, stdout=resp, stderr=err, msg="Error occurred while setting configuration variables")

            if unset_changes:
                unset_cmd += '-a ' + app
                unset_rc, resp, err = module.run_command(unset_cmd)
                if unset_rc != 0:
                   module.fail_json(changed=False, rc=rc, stdout=resp, stderr=err, msg="Error occurred while unsetting configuration variables")

            if not set_changes and not unset_changes:
                module.exit_json(changed=False, msg="Configuration up-to-date")
            elif set_rc == 0 and unset_rc == 0:
                module.exit_json(changed=True, msg=app + " configured Successfully")
            else:
                module.fail_json(changed=False, msg="Error occurred while configuring " + app)

    elif action == 'pull':
        if app is None or app_ver is None or source is None:
            module.fail_json(msg="App name or/and app version or/and domain or/and source not provided")
        else:
            releases_cmd = deis + " releases -a " + app
            rc, resp, err = module.run_command(releases_cmd)

            if 'deployed' in resp:
                ver_deployed = resp[resp.index(':', resp.index('deployed'))+1:resp.index('\n', resp.index('deployed'))]
                if ver_deployed.strip() == '':
                    ver_deployed = "undefined"
            else:
                ver_deployed = None

            if ver_deployed is None or ver_deployed != app_ver:
                cmd = deis + " pull " + source + " -a " + app
                rc, resp, err = module.run_command(cmd)

                if rc == 0:
                    module.exit_json(changed=True, msg=app + " deployed successfully")
                else:
                    module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while deploying " + app)
            else:
                module.exit_json(changed=False, msg="Latest version already deployed")

    elif action == 'domain':
        if app is None or domain is None:
            module.fail_json(msg="App name or/and domain not provided")
        else:
            list_domains = deis + " domains:list -a " + app
            rc, resp, err = module.run_command(list_domains)
            resp = resp[resp.index('\n')+1:]
            deis_domains_list = resp.split('\n')

            app_domain = app_name_for_domain + "." + domain
            if app_domain in deis_domains_list:
                module.exit_json(changed=False, msg="Domain " + app_domain + " already exists for " + app)
            else:
                cmd = deis + " domains:add " + app_domain + " -a " + app
                rc, resp, err = module.run_command(cmd)
                if rc == 0:
                    module.exit_json(changed=True, msg="Domain " + app_domain + " added successfully for " + app)
                else:
                    module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while adding domain " + app_domain + " for " + app)

    elif action == 'scale':
        if app is None or scale is None:
            module.fail_json(msg="App name or/and scale not provided")
        else:
            scale_cmd = deis + " apps:info -a " + app
            rc, resp, err = module.run_command(scale_cmd)
            containers = __count_container(resp, app)
            scale = int(scale)

            if scale == containers:
                module.exit_json(changed=False, msg="Number of containers for " +  app + " is already " + str(scale))
            else:
                cmd = deis + " scale cmd=" + str(scale) + " -a " + app
                rc, resp, err = module.run_command(cmd)

                if rc == 0:
                    module.exit_json(changed=True, msg=app + " scaled to " + str(scale) + " successfully")
                else:
                    module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while scaling " + app)

    elif action == 'make_admin':
        if username is None:
            module.fail_json(msg="Username not provided")
        else:
            list_perms = deis + " perms:list --admin"
            rc, resp, err = module.run_command(list_perms)
            resp = resp[resp.index('\n')+1:]
            deis_perms_list = resp.split('\n')

            if username in deis_perms_list:
                module.exit_json(changed=False, msg="User " + username + " already has admin rights")
            else:
                cmd = deis + " perms:create " + username + " --admin"
                rc, resp, err = module.run_command(cmd)
                if rc == 0:
                    module.exit_json(changed=True, msg="User " + username + " successfully given admin privileges")
                else:
                    module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while assigning admin rights to " + username)

    else:
        module.fail_json(changed=False, msg="Invalid Action")


def __count_container(info, app):
    containers = 0
    info = info[info.index('=== ' + app + ' Processes'):info.index('=== ' + app + ' Domains')]
    info_list = info.split('\n')
    for info in info_list:
        if "up" in info:
            containers += 1
    return containers


# import module snippets
from ansible.module_utils.basic import *

main()
