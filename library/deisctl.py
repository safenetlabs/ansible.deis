#!/usr/bin/python


def main():

    module = AnsibleModule(
        argument_spec=dict(
            action=dict(type='str', required=False),
            domain=dict(type='str', required=False),
            unit_hostname=dict(type='str', required=False),
            drain=dict(type='str', required=False),
            units=dict(type='str', required=False),
            target=dict(type='str', required=False),
        )
    )

    action = module.params['action']
    domain = module.params['domain']
    unit_hostname = module.params['unit_hostname']
    drain = module.params['drain']
    units = module.params['units']
    target = module.params['target']
    deisctl = "/opt/bin/deisctl"

    if action == '':
        module.fail_json(msg="No action provided")

    elif action == 'refresh':
        cmd = deisctl + ' refresh-units'
        rc, resp, err = module.run_command(cmd)
        if rc == 0:
            module.exit_json(changed=True, msg="Units refreshed successfully")
        else:
            module.exit_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error refreshing units")

    elif action == 'configure':
        config_dict = {'domain': domain, 'unitHostname': unit_hostname, 'drain': drain}
        is_changed = False
        for key, val in config_dict.iteritems():
            get_config = deisctl + ' config platform get ' + key
            rc, resp, err = module.run_command(get_config)
            if resp.rstrip() != val:
                cmd = deisctl + ' config platform set ' + key + '=' + val
                rc, resp, err = module.run_command(cmd)
                if rc != 0:
                    module.exit_json(changed=False, cmd=cmd, rc=rc, stdout=resp, stderr=err, msg="Error occurred while configuring platform")
                is_changed = True

        if is_changed:
            module.exit_json(changed=True, msg="Platform configured successfully")
        else:
            module.exit_json(changed=False, msg="Configuration up-to-date")

    elif action == 'install_platform':
        cmd = deisctl + ' status deis-database.service'
        rc, resp, err = module.run_command(cmd)
        if rc == 0:
            module.exit_json(changed=False, msg="Platform already installed")
        else:
            cmd = deisctl + ' install platform'
            rc, resp, err = module.run_command(cmd)

            start_cmd = deisctl + ' start platform'
            start_rc, start_resp, start_err = module.run_command(start_cmd)

            if rc == 0 and start_rc == 0:
                module.exit_json(changed=True, msg="Platform installed and started successfully")
            elif rc != 0:
                module.exit_json(changed=False, cmd=cmd, rc=rc, stderr=err, msg="Error occurred while installing platform")
            elif start_rc != 0:
                module.exit_json(changed=False, cmd=start_cmd, rc=start_rc, stderr=start_err, msg="Error occurred while starting platform")
            else:
                module.exit_json(changed=False, msg="Error occurred while installing or/and starting platform")

    elif action == 'scale':
        if target is None or units is None:
            module.fail_json(msg="target or/and units not provided")
        else:
            cmd = deisctl + ' scale ' + target + '=' + units
            rc, resp, err = module.run_command(cmd)

            if rc == 0:
                module.exit_json(changed=True, msg="Router scaled successfully")
            else:
                module.fail_json(changed=False, cmd=cmd, rc=rc, stderr=err, stdout=resp, msg="Error scaling router")

    else:
        module.fail_json(changed=False, msg="Invalid Action")


# import module snippets
from ansible.module_utils.basic import *

main()
