import click
import utilities_common.cli as clicommon

#
# This group houses Spanning_tree commands and subgroups
#
@click.group(cls=clicommon.AliasedGroup, default_if_no_args=False, invoke_without_command=True)
@click.pass_context
def spanning_tree(ctx):
    '''debug spanning_tree commands'''
    if ctx.invoked_subcommand is None:
        command = 'sudo stpctl dbg enable'
        clicommon.run_command(command)

@spanning_tree.group('dump', cls=clicommon.AliasedGroup, default_if_no_args=False, invoke_without_command=True)
def stp_debug_dump():
    pass

@stp_debug_dump.command('global')
def stp_debug_dump_global():
    command = 'sudo stpctl global'
    clicommon.run_command(command)

@stp_debug_dump.command('vlan')
@click.argument('vlan_id', metavar='<vlan_id>', required=True)
def stp_debug_dump_vlan(vlan_id):
    command = 'sudo stpctl vlan ' + vlan_id
    clicommon.run_command(command)

@stp_debug_dump.command('interface')
@click.argument('vlan_id', metavar='<vlan_id>', required=True)
@click.argument('interface_name', metavar='<interface_name>', required=True)
def stp_debug_dump_vlan_intf(vlan_id, interface_name):
    command = 'sudo stpctl port ' + vlan_id + " " + interface_name
    clicommon.run_command(command)

@spanning_tree.command('show')
def stp_debug_show():
    command = 'sudo stpctl dbg show'
    clicommon.run_command(command)

@spanning_tree.command('reset')
def stp_debug_reset():
    command = 'sudo stpctl dbg disable'
    clicommon.run_command(command)

@spanning_tree.command('bpdu')
@click.argument('mode', metavar='{rx|tx}', required=False)
@click.option('-d', '--disable', is_flag=True)
def stp_debug_bpdu(mode, disable):
    if disable:
        if mode == 'rx':
            command = 'sudo stpctl dbg bpdu rx-off'
        elif mode == 'tx':
            command = 'sudo stpctl dbg bpdu tx-off'
        else:
            command = 'sudo stpctl dbg bpdu off'
    else:
        if mode == 'rx':
            command = 'sudo stpctl dbg bpdu rx-on'
        elif mode == 'tx':
            command = 'sudo stpctl dbg bpdu tx-on'
        else:
            command = 'sudo stpctl dbg bpdu on'
    clicommon.run_command(command)

@spanning_tree.command('verbose')
@click.option('-d', '--disable', is_flag=True)
def stp_debug_verbose(disable):
    if disable:
        command = 'sudo stpctl dbg verbose off'
    else:
        command = 'sudo stpctl dbg verbose on'
    clicommon.run_command(command)

@spanning_tree.command('event')
@click.option('-d', '--disable', is_flag=True)
def stp_debug_event(disable):
    if disable:
        command = 'sudo stpctl dbg event off'
    else:
        command = 'sudo stpctl dbg event on'
    clicommon.run_command(command)

@spanning_tree.command('vlan')
@click.argument('vlan_id', metavar='<vlan_id/all>', required=True)
@click.option('-d', '--disable', is_flag=True)
def stp_debug_vlan(vlan_id, disable):
    if disable:
        command = 'sudo stpctl dbg vlan ' + vlan_id + ' off'
    else:
        command = 'sudo stpctl dbg vlan ' + vlan_id + ' on'
    clicommon.run_command(command)

@spanning_tree.command('interface')
@click.argument('interface_name', metavar='<interface_name/all>', required=True)
@click.option('-d', '--disable', is_flag=True)
def stp_debug_intf(interface_name, disable):
    if disable:
        command = 'sudo stpctl dbg port ' + interface_name + ' off'
    else:
        command = 'sudo stpctl dbg port ' + interface_name + ' on'
    clicommon.run_command(command)


