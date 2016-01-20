#!/usr/bin/python
import os
import re
import urllib

deis = "/opt/bin/deis"
deisctl = "/opt/bin/deisctl"

def finished(module, subroutine=False, **kwargs):
    if not subroutine:
        module.exit_json(**kwargs)
    return kwargs

def whoami(module):
    is_logged_in = deis + " whoami"
    rc, resp, err = module.run_command(is_logged_in)
    if rc != 0:
        return None
    return resp[resp.index('You are ')+8:resp.index(' at http')]

def install_deis(module, version=None):
    deis_current_version=None
    deisctl_current_version=None
    if not version:
        version = module.params['version']
    if not version:
        module.fail_json(changed=False, msg="No version specified")
    if os.path.exists(deis):
        _, resp, _ = module.run_command(deis + ' --version')
        deis_current_version = resp.strip()
        _, resp, _ = module.run_command(deisctl + ' --version')
        deisctl_current_version = resp.strip()
        if deisctl_current_version != version or deis_current_version != version:
            module.fail_json(changed=False,
                             msg="Another version is already installed.",
                             version_mismatch=True,
                             deis_version=deis_current_version,
                             deisctl_version=deisctl_current_version)
        module.exit_json(changed=False,
                         msg="DEIS already installed",
                         deis_version=deis_current_version,
                         deisctl_version=deisctl_current_version)

    if not module.check_mode:
        os.chdir('/opt/bin/')
        urllib.urlretrieve('http://deis.io/deis-cli/install.sh', 'install.sh')
        cmd = 'sh install.sh ' + version
        rc, resp, err = module.run_command(cmd)
        os.remove('/opt/bin/install.sh')
        if rc != 0:
            module.fail_json(changed=False,
                             cmd=cmd,
                             rc=rc,
                             stdout=resp,
                             stderr=err,
                             version=version,
                             deis_version=deis_current_version,
                             deisctl_version=deisctl_current_version,
                             msg="Error occurred while installing DEIS")
    module.exit_json(changed=True, msg="DEIS installed successfully", version=version, deis_version=version, deisctl_version=version)

def logout(module, subroutine=False):
    if module.check_mode:
        current_user = whoami(module)
        if current_user:
            return finished(module, changed=True, msg="Would logout", user=current_user)
        else:
            module.exit_json(changed=False, msg="No one currently logged in")

    cmd = deis + " logout"
    rc, resp, err = module.run_command(cmd)

    if rc == 0:
        return finished(module, subroutine=subroutine, changed=True, msg="Logout Successful", stdout=resp)
    else:
        module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while logging out")

def register(module, subroutine=False, username=None, password=None,email=None,domain=None):
    if not username: username = module.params['username']
    if not password: password = module.params['password']
    if not domain: domain = module.params['domain']
    if not email: email = module.params['email']

    if not username or not password or not email or not domain:
        module.fail_json(msg="Username, password, domain or email not provided")

    rc, resp, _ = module.run_command(deis + " users")
    if rc == 0 and username in resp.splitlines()[1:]:
        return finished(module, subroutine=subroutine, changed=False, msg="Already registered", username=username)

    full_action = "auth:register deis." + domain
    cmd = deis + " " + full_action + " --username=" + username + " --password=" + password + " --email=" + email
    if not module.check_mode:
        rc, resp, err = module.run_command(cmd)

        if rc != 0:
            if "This field must be unique" in err:
                return finished(module, subroutine=subroutine, changed=False, msg="User already exists")
            else:
                module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while registering user")

    return finished(module, subroutine=subroutine, changed=True, msg="User registered Successfully")


def login(module, username=None, password=None, domain=None):
    if not username: username = module.params['username']
    if not password: password = module.params['password']
    if not domain: domain = module.params['domain']
    if not username or not password or not domain:
        module.fail_json(msg="Username, password, or/and domain not provided")
    current_user = whoami(module)
    if current_user == username:
        module.exit_json(changed=False, msg="Already logged in")
    if current_user:
        logout(module, subroutine=True)
    full_action = "auth:login deis." + domain
    cmd = deis + " " + full_action + " --username=" + username + " --password=" + password
    resp = ""
    if not module.check_mode:
        rc, resp, err = module.run_command(cmd)
        if rc != 0:
            module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while logging in")
    module.exit_json(changed=True, msg="Login Successful", prior_user=current_user, new_user=username, stdout=resp)

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
            config_dict=dict(type='dict', required=False),
            app_ver=dict(type='str', required=False),
            scale=dict(type='str', required=False),
            source=dict(type='str', required=False),
            certfile=dict(type='str', required=False),
            keyfile=dict(type='str', required=False),
            version=dict(type='str', required=False),
            register=dict(type='bool', required=False)
        ),
        supports_check_mode=True
    )

    action = module.params['action']

    username = module.params['username']
    domain = module.params['domain']
    app_name_for_domain = module.params['app_name_for_domain']
    app = module.params['app']
    config_vars = module.params['config_vars']
    config_dict = module.params['config_dict']
    app_ver = module.params['app_ver']
    scale = module.params['scale']
    source = module.params['source']
    certfile = module.params['certfile']
    keyfile = module.params['keyfile']

    if action == '':
        module.fail_json(msg="No action provided")

    elif action == 'install_deis':
        install_deis(module)

    elif action == 'register':
        register(module)

    elif action == 'login':
        login(module)

    elif action == 'logout':
        logout(module)

    elif action == 'create':
        if app is None:
            module.fail_json(msg="App name not provided")
        if module.check_mode:
            cmd = deis + " apps"
            rc, resp, err = module.run_command(cmd)
            if app in resp.splitlines():
                module.exit_json(changed=False, msg=app + " already exists")
            else:
                module.exit_json(changed=True, msg="Will create " + app)

        cmd = deis + " apps:create --no-remote " + app
        rc, resp, err = module.run_command(cmd)

        if rc == 0:
            module.exit_json(changed=True, msg=app + " created successfully", stdout=resp)

        if "This field must be unique" in err:
            module.exit_json(changed=False, msg=app + " already exists")
        else:
            module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while creating " + app)

    elif action == 'configure':
        set_keys = []
        unset_keys = []
        if not app or (not config_vars and not config_dict ):
            module.fail_json(msg="App Name or/and config variables not provided")

        list_cmd = deis + " config:list -a " + app
        rc, resp, err = module.run_command(list_cmd)
        resp = resp[resp.index('\n')+1:]

        if config_dict:
            input_vars_dict = config_dict
        else:
            input_vars_dict = dict([s.strip() for s in var.split('=', 1)] for var in config_vars.split('\\\n'))
        # Convert values to strings
        input_vars_dict = {k: str(v) for (k,v) in input_vars_dict.iteritems()}

        deis_vars_list = resp.splitlines()
        deis_vars_dict = dict([s.strip() for s in var.split(' ', 1)] for var in deis_vars_list)

        set_cmd = deis + " config:set "
        unset_cmd = deis + " config:unset "
        set_rc = 0
        unset_rc = 0

        for key, val in input_vars_dict.iteritems():
            if key not in deis_vars_dict or deis_vars_dict[key] != val:
                if key == "SSH_KEY" and key in deis_vars_dict:
                    continue
                set_cmd += key + '=' + val + ' '
                set_keys.append(dict(key=key, oldval=deis_vars_dict.get(key), newval=val))

        for key, val in deis_vars_dict.iteritems():
            if key not in input_vars_dict:
                unset_cmd += key + ' '
                unset_keys.append(key)

        if set_keys and not module.check_mode:
            set_cmd += '-a ' + app
            # set_rc, resp, err = run_deis_command(set_cmd, pause=True)
            set_rc, resp, err = module.run_command(set_cmd)
            if set_rc != 0:
               module.fail_json(changed=False, rc=rc, stdout=resp, stderr=err, msg="Error occurred while setting configuration variables")

        if unset_keys and not module.check_mode:
            unset_cmd += '-a ' + app
            unset_rc, resp, err = module.run_command(unset_cmd)
            # unset_rc, resp, err = run_deis_command(unset_cmd, pause=True)
            if unset_rc != 0:
               module.fail_json(changed=False, rc=rc, stdout=resp, stderr=err, msg="Error occurred while unsetting configuration variables")

        if not set_keys and not unset_keys:
            module.exit_json(changed=False, msg="Configuration up-to-date")
        elif set_rc == 0 and unset_rc == 0:
            module.exit_json(changed=True, msg=app + " configured Successfully", set_keys=set_keys, unset_keys=unset_keys)
        else:
            module.fail_json(changed=False, msg="Error occurred while configuring " + app, set_keys=set_keys, unset_keys=unset_keys)

    elif action == 'pull':
        if app is None or app_ver is None or source is None:
            module.fail_json(msg="App name or/and app version or/and domain or/and source not provided")

        releases_cmd = deis + " releases -a " + app
        rc, resp, err = module.run_command(releases_cmd)

        ver_deployed = None
        if 'deployed' in resp:
            ver_deployed = resp[resp.index(':', resp.index('deployed'))+1:resp.index('\n', resp.index('deployed'))]
            if ver_deployed.strip() == '':
                ver_deployed = "undefined"

        if ver_deployed == app_ver:
            module.exit_json(changed=False, msg="Latest version already deployed")

        cmd = deis + " pull " + source + " -a " + app
        if not module.check_mode:
            rc, resp, err = module.run_command(cmd)
            if rc != 0:
                module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while deploying " + app)

        module.exit_json(changed=True, msg=app + " deployed from " + str(ver_deployed) + " to " + str(app_ver) + " successfully")


    elif action == 'domain':
        if app is None or domain is None:
            module.fail_json(msg="App name or/and domain not provided")

        list_domains = deis + " domains:list -a " + app
        rc, resp, err = module.run_command(list_domains)
        resp = resp[resp.index('\n')+1:]
        deis_domains_list = resp.split('\n')

        app_domain = app_name_for_domain + "." + domain
        if app_domain in deis_domains_list:
            module.exit_json(changed=False, msg="Domain " + app_domain + " already exists for " + app)
        cmd = deis + " domains:add " + app_domain + " -a " + app
        if not module.check_mode:
            rc, resp, err = module.run_command(cmd)
            if rc != 0:
                module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while adding domain " + app_domain + " for " + app)
        module.exit_json(changed=True, msg="Domain " + app_domain + " added successfully for " + app)

    elif action == 'scale':
        if app is None or scale is None:
            module.fail_json(msg="App name or/and scale not provided")

        scale_cmd = deis + " apps:info -a " + app
        rc, resp, err = module.run_command(scale_cmd)
        containers = __count_container(resp, app)
        scale = int(scale)

        if scale == containers:
            module.exit_json(changed=False, msg="Number of containers for " +  app + " is already " + str(scale))

        cmd = deis + " scale cmd=" + str(scale) + " -a " + app
        if not module.check_mode:
            rc, resp, err = module.run_command(cmd)
            if rc != 0:
                module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while scaling " + app)

        module.exit_json(changed=True, msg=app + " scaled from " + str(containers) + " to " + str(scale) + " successfully")

    elif action == 'make_admin':
        if username is None:
            module.fail_json(msg="Username not provided")

        list_perms = deis + " perms:list --admin"
        rc, resp, err = module.run_command(list_perms)
        resp = resp[resp.index('\n')+1:]
        deis_perms_list = resp.split('\n')

        if username in deis_perms_list:
            module.exit_json(changed=False, msg="User " + username + " already has admin rights")

        cmd = deis + " perms:create " + username + " --admin"
        if not module.check_mode:
            rc, resp, err = module.run_command(cmd)
            if rc != 0:
                module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while assigning admin rights to " + username)
        module.exit_json(changed=True, msg="User " + username + " successfully given admin privileges")

    elif action == 'add_cert':
        if module.check_mode:
            module.exit_json(changed=False, msg="check mode not supported for this action")

        if certfile is None or keyfile is None:
            module.fail_json(msg="keyfile or certfile not provided")

        cmd = deis +  " certs:add " + certfile + " " + keyfile

        rc, resp, err = module.run_command(cmd)
        if rc == 0:
            module.exit_json(changed=True, msg="Successfully added certificate")
        elif "500 INTERNAL SERVER ERROR" in err:
            module.exit_json(changed=False, stderr=err, msg="Key PROBABLY already exists - no good way to tell from command error.")
        else:
            module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while adding certificate")

    elif action == 'add_key':
        if module.check_mode:
            module.exit_json(changed=False, msg="check mode not supported for this action")

        if certfile is None:
            module.fail_json(msg="certfile not provided")

        cmd = deis + ' keys:add ' + certfile
        rc, resp, err = module.run_command(cmd)
        if rc == 0:
            module.exit_json(changed=True, msg="Successfully added key")
        elif "This field must be unique" in err:
            module.exit_json(changed=False, msg="Key already exists")
        else:
            module.fail_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while adding key")
    else:
        module.fail_json(changed=False, msg="Invalid Action")




def __count_container(info, app):
    info = info[info.index('=== ' + app + ' Processes'):info.index('=== ' + app + ' Domains')]
    return len([l for l in info.splitlines() if re.match("^cmd.\d+ ((up)|(down))", l)])


# import module snippets
from ansible.module_utils.basic import *

main()
