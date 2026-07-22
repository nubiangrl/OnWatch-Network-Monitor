"""Core monitoring loop orchestration for On Watch Network Monitor."""

def run_monitoring_engine(namespace):
    while True:
        namespace['load_config']()
        namespace['discover_infrastructure_interfaces']()
        namespace['discover_cdp_neighbors']()
        namespace['discover_lldp_neighbors']()
        namespace['build_link_confidence_database']()
        if bool(namespace['config'].get('infrastructure_auto_linking', {}).get('rebuild_after_discovery', True)):
            namespace['rebuild_auto_infrastructure_links']()
        namespace['check_topology_changes']()
        scheduled_changed = namespace['apply_scheduled_maintenance']()
        maintenance_changed = namespace['cleanup_expired_maintenance']()
        provisioning_changed = namespace['cleanup_expired_provisioning_grace']()
        if scheduled_changed or maintenance_changed or provisioning_changed:
            namespace['save_config']()
            namespace['load_config']()
        namespace['update_internet_uptime_tracking']()
        for name, ip in namespace['DEVICES'].items():
            maintenance_info = namespace['get_device_maintenance_info'](name)
            if maintenance_info:
                namespace['status'][name] = {'ip': ip, 'state': namespace['get_maintenance_state_label'](), 'raw_state': 'MAINTENANCE', 'latency': f"Maintenance: {maintenance_info.get('reason', 'Maintenance')}", 'raw_latency': 'N/A', 'sleep_allowed': namespace['is_sleep_allowed_device'](name), 'sleep_grace_minutes': namespace['get_sleep_grace_minutes'](), 'maintenance_mode': True, 'maintenance_reason': maintenance_info.get('reason', 'Maintenance'), 'maintenance_remaining': namespace['format_maintenance_remaining'](maintenance_info.get('remaining_seconds', -1)), 'last_checked': namespace['now'](), 'last_change': maintenance_info.get('start', namespace['now']())}
                namespace['previous_status'][name] = namespace['get_maintenance_state_label']()
                continue
            grace_info = namespace['get_device_provisioning_grace'](name)
            if grace_info:
                namespace['status'][name] = {'ip': ip, 'state': namespace['get_provisioning_state_label'](), 'raw_state': 'PROVISIONING', 'latency': f"Provisioning grace: {grace_info.get('remaining_seconds', 0)}s", 'raw_latency': 'N/A', 'sleep_allowed': namespace['is_sleep_allowed_device'](name), 'sleep_grace_minutes': namespace['get_sleep_grace_minutes'](), 'provisioning_grace': True, 'grace_remaining_seconds': grace_info.get('remaining_seconds', 0), 'last_checked': namespace['now'](), 'last_change': grace_info.get('start', namespace['now']())}
                namespace['previous_status'][name] = namespace['get_provisioning_state_label']()
                continue
            raw_state, latency = namespace['check_device'](ip)
            old_raw_state = namespace['previous_status'].get(name)
            old_effective_state = namespace['status'].get(name, {}).get('state')
            previous_last_change = namespace['status'].get(name, {}).get('last_change', 'Starting...')
            if old_raw_state != raw_state:
                effective_last_change = namespace['now']()
            else:
                effective_last_change = previous_last_change
            effective_state = namespace['apply_sleep_detection_state'](name, raw_state, effective_last_change)
            effective_latency = latency
            if effective_state == namespace['get_sleep_status_label']():
                effective_latency = 'Sleeping'
            if old_effective_state and old_effective_state != effective_state:
                if effective_state == namespace['get_sleep_status_label']():
                    namespace['write_event'](f'SLEEP | DEVICE | {name} ({ip}) entered sleep detection window')
                elif old_effective_state == namespace['get_sleep_status_label']() and effective_state == 'UP':
                    namespace['total_recoveries'] += 1
                    namespace['write_event'](f'WAKE | DEVICE | {name} ({ip}) woke from sleep and changed to UP')
                elif effective_state == 'DOWN':
                    namespace['total_alerts'] += 1
                    transition_problem = 'Device DOWN'
                    if namespace['is_sleep_allowed_device'](name):
                        namespace['write_event'](f'ALERT | DEVICE | {name} ({ip}) exceeded sleep detection grace window and changed to DOWN')
                        transition_problem = 'Device exceeded sleep detection grace window and changed to DOWN'
                    else:
                        namespace['write_event'](f'ALERT | DEVICE | {name} ({ip}) changed from {old_effective_state} to DOWN')
                    namespace['register_alert_transition'](source='device', device=name, problem=transition_problem, previous_state=old_effective_state, current_state=effective_state, severity=namespace['classify_alert_severity'](name, transition_problem, 'device'))
                elif effective_state == 'UP':
                    namespace['total_recoveries'] += 1
                    namespace['write_event'](f'RECOVERY | DEVICE | {name} ({ip}) changed from {old_effective_state} to UP')
                    namespace['register_recovery_transition'](source='device', device=name, problem='Device DOWN', previous_state=old_effective_state, current_state=effective_state, severity='INFO')
                elif effective_state == 'ERROR':
                    namespace['write_event'](f'ERROR | DEVICE | {name} ({ip}) changed from {old_effective_state} to ERROR')
            namespace['status'][name] = {'ip': ip, 'state': effective_state, 'raw_state': raw_state, 'latency': effective_latency, 'raw_latency': latency, 'sleep_allowed': namespace['is_sleep_allowed_device'](name), 'sleep_grace_minutes': namespace['get_sleep_grace_minutes'](), 'last_checked': namespace['now'](), 'last_change': effective_last_change}
            namespace['previous_status'][name] = raw_state
        for old_device in list(namespace['status'].keys()):
            if old_device not in namespace['DEVICES'] and old_device != namespace['get_internet_service_name']():
                namespace['status'].pop(old_device, None)
                namespace['previous_status'].pop(old_device, None)
        new_router_interfaces = namespace['get_router_interfaces']()
        for index, info in new_router_interfaces.items():
            old_state = namespace['previous_router_interfaces'].get(index)
            if old_state and old_state != info['state']:
                if info['state'] == 'DOWN':
                    namespace['total_alerts'] += 1
                    namespace['write_event'](f"ALERT | ROUTER LINK | {info['name']} changed from {old_state} to DOWN")
                    namespace['register_alert_transition'](source='router_link', device=info.get('short_name', info.get('name', 'Router Link')), problem='Router Link DOWN', previous_state=old_state, current_state=info.get('state', 'DOWN'), severity='CRITICAL', port=info.get('short_name', ''), root_cause=info.get('name', 'Router Link'))
                elif info['state'] == 'UP':
                    namespace['total_recoveries'] += 1
                    namespace['write_event'](f"RECOVERY | ROUTER LINK | {info['name']} changed from {old_state} to UP")
                    namespace['register_recovery_transition'](source='router_link', device=info.get('short_name', info.get('name', 'Router Link')), problem='Router Link DOWN', previous_state=old_state, current_state=info.get('state', 'UP'), severity='INFO', port=info.get('short_name', ''), root_cause=info.get('name', 'Router Link'))
            namespace['previous_router_interfaces'][index] = info['state']
        namespace['router_interfaces'] = new_router_interfaces
        new_switch_links = namespace['get_switch_links']()
        for index, info in new_switch_links.items():
            old_state = namespace['previous_switch_links'].get(index)
            if info.get('maintenance_mode') or info.get('state') == namespace['get_maintenance_state_label']() or info.get('provisioning_grace') or (info.get('state') == namespace['get_provisioning_state_label']()):
                namespace['previous_switch_links'][index] = info['state']
                continue
            if old_state and old_state != info['state']:
                if info['state'] == 'DOWN':
                    namespace['total_alerts'] += 1
                    namespace['write_event'](f"ALERT | SWITCH LINK | {info['device']} on {info['port']} changed from {old_state} to DOWN")
                    namespace['register_alert_transition'](source='switch_link', device=info.get('device', 'Switch Link'), problem='Switch Link DOWN', previous_state=old_state, current_state=info.get('state', 'DOWN'), severity=namespace['classify_alert_severity'](info.get('device', 'Switch Link'), 'Switch Link DOWN', 'switch'), port=info.get('port', ''), root_cause=f"Switch Port {info.get('port', '')}")
                elif info['state'] == 'UP':
                    namespace['total_recoveries'] += 1
                    namespace['write_event'](f"RECOVERY | SWITCH LINK | {info['device']} on {info['port']} changed from {old_state} to UP")
                    namespace['register_recovery_transition'](source='switch_link', device=info.get('device', 'Switch Link'), problem='Switch Link DOWN', previous_state=old_state, current_state=info.get('state', 'UP'), severity='INFO', port=info.get('port', ''), root_cause=f"Switch Port {info.get('port', '')}")
            namespace['previous_switch_links'][index] = info['state']
        namespace['switch_links'] = new_switch_links
        namespace['apply_switch_link_override_to_device_status'](new_switch_links)
        namespace['last_full_scan'] = namespace['now']()
        namespace['analyze_root_cause_topology']()
        namespace['time'].sleep(namespace['CHECK_INTERVAL'])
