
# Copyright (c) 2017 Aviatrix Systems, Inc.
''' 
backend-services for GCE controller instance monitoring 
usage:
python gce_backend_service.py <instance name> <instance zone> <project credentials> 
Eg:
python gce_backend_service.py dry-test us-east1-b /var/cloudx/ucc-gcloud.json
'''
import logging
import json
import subprocess
import os
import time
import argparse
POLL_TIME = 30


class BackendServiceErr(Exception):
    ''' Exception handler for BackendService '''
    pass

class RunOsCommandsErr(Exception):
    ''' Exception for exec errors '''
    pass


class BackendService(object):
    ''' GCE backend-services '''


    def __init__(self, instance_name, zone, path_to_cert):
        self.logger = logging.getLogger('backend')
        self.instance_name = instance_name
        self.zone = zone
        print 'Validating credential file'
        cer_project, reason = self._get_project_id(path_to_cert)
        if not cer_project:
            raise BackendServiceErr(reason)
        self.project = cer_project
        self.path_to_cert = path_to_cert
        self.ig_name = instance_name + '-ig'
        self.svc_name = instance_name + '-svc1'
        self.protocol = "HTTPS"
        self.health_name = instance_name + '-' + self.protocol.lower()
        print 'Using the credential file to set service account'
        if not set_service_account(self.project, path_to_cert):
            reason = 'Project context switch failed for "{}"'.\
                     format(instance_name)
            self.logger.error(reason)
            raise BackendServiceErr(reason)
        print 'Validating supplied zone'
        self.test_zone()
        print 'Supplied zone is in GCE list'
        self.test_instance_name()
        self.del_status = ''
        self.was_helathy = False


    def test_zone(self):
        ''' get the zones list and test with supplied one '''
        cmd = 'gcloud compute zones list --format json'
        try:
            result = run_os_command(cmd)
        except RunOsCommandsErr as err:
            self.logger.error(err)
            raise BackendServiceErr(str(err))
        all_zones = json.loads(result)
        for zone in all_zones:
            if zone['name'] == self.zone:
                return
        reason = 'Supplied Zone {} is not in GCE.'.format(self.zone)
        raise BackendServiceErr(reason)


    def test_instance_name(self):
        ''' get the instance list and test with supplied one '''
        cmd = 'gcloud compute instances list {} --format json'
        cmd = cmd.format(self.instance_name)
        try:
            result = run_os_command(cmd)
        except RunOsCommandsErr as err:
            self.logger.error('Unable to get instance info')
            self.logger.error(err)
            raise BackendServiceErr(str(err))
        infoj = json.loads(result)
        if not infoj:
            reason = 'The given instance name:{} is not there in the given zone:{}'
            reason = reason.format(self.instance_name, self.zone)
            raise BackendServiceErr(reason)
        try:
            info = infoj[0]
        except IndexError as err:
            self.logger.error(infoj)
            raise BackendServiceErr(str(err))
        if info.get('name') != self.instance_name:
            reason = 'The supplied instance_name not found in the given zone'
            raise BackendServiceErr(reason)
        if info.get('zone') != self.zone:
            reason = 'The supplied Zone not match with the instance Zone'
            raise BackendServiceErr(reason)
        print 'Credential, zone and instance sanity test passed'


    @staticmethod
    def _get_project_id(path_to_json):
        ''' open and return gce project id from credential file '''
        reason = None
        if not path_to_json:
            reason = 'Project Credentials JSON key-file is NOT supplied'
            self.logger.error(reason)
            return None, reason
        if not os.path.exists(path_to_json):
            reason = 'Supplied project Credentials JSON key-file not found'
            self.logger.error(reason)
            return None, reason
        with open(path_to_json, 'r') as f_d:
            try:
                cer_data = json.load(f_d)
            except ValueError:
                reason = 'credentials file is not JSON object'
                self.logger.error(reason)
                return None, reason
        cer_project = cer_data.get('project_id')
        if not cer_project:
            reason = 'Not a valied GCE credentials file'
        return cer_project, reason


    @staticmethod
    def create_fail_ok(err):
        ''' check the failure due to already exists '''
        if ' already exists' in str(err):
            self.logger.info('resource already exists. Ignore')
            return True
        return False


    def create_instance_groups(self):
        ''' create instance-groups '''
        cmd = 'gcloud compute instance-groups unmanaged create {} ' + \
              '--zone {} --format json'
        cmd = cmd.format(self.ig_name, self.zone)
        self.logger.info(cmd)
        try:
            result = run_os_command(cmd)
            self.logger.info(result)
        except RunOsCommandsErr as err:
            self.logger.info(str(err))
            if not self.create_fail_ok(err):
                raise BackendServiceErr(err)


    def add_instances_to_ig(self):
        ''' add instance to instance-groups '''
        cmd = 'gcloud compute instance-groups unmanaged ' + \
              'add-instances {} ' + \
              '--zone {} --instances {} --format json'
        cmd = cmd.format(self.ig_name,
                         self.zone,
                         self.instance_name)
        self.logger.info(cmd)
        try:
            result = run_os_command(cmd)
            self.logger.info(result)
        except RunOsCommandsErr as err:
            self.logger.info(str(err))
            if not self.create_fail_ok(err):
                self.delete_instance_groups()
                raise BackendServiceErr(err)


    def create_health_checks(self):
        ''' add health-checks '''
        cmd = 'gcloud compute https-health-checks create {} ' + \
              '--check-interval 10s --unhealthy-threshold 2 ' + \
              ' --format json'
        cmd = cmd.format(self.health_name)
        self.logger.info(cmd)
        try:
            result = run_os_command(cmd)
            self.logger.info(result)
        except RunOsCommandsErr as err:
            self.logger.info(str(err))
            if not self.create_fail_ok(err):
                self.remove_instances_from_ig()
                self.delete_instance_groups()
                raise BackendServiceErr(err)


    def create_backend_services(self):
        ''' create backend-services '''
        cmd = 'gcloud compute backend-services create {} ' + \
              '--https-health-check {} --protocol {} ' + \
                '--format json'
        cmd = cmd.format(self.svc_name,
                         self.health_name,
                         self.protocol)
        self.logger.info(cmd)
        try:
            result = run_os_command(cmd)
            self.logger.info(result)
        except RunOsCommandsErr as err:
            self.logger.info(str(err))
            if not self.create_fail_ok(err):
                self.remove_instances_from_ig()
                self.delete_instance_groups()
                self.delete_health_checks()
                raise BackendServiceErr(err)


    def add_backend_to_services(self):
        ''' add backend to backend-services '''
        cmd = 'gcloud compute backend-services add-backend {} ' + \
              '--balancing-mode UTILIZATION --max-utilization 1 ' + \
              '--capacity-scaler 1.0 --instance-group {} ' + \
              '--zone {} --format json'
        cmd = cmd.format(self.svc_name,
                         self.ig_name,
                         self.zone)
        self.logger.info(cmd)
        try:
            result = run_os_command(cmd)
            self.logger.info(result)
        except RunOsCommandsErr as err:
            self.logger.info(str(err))
            if not self.create_fail_ok(err):
                self.remove_instances_from_ig()
                self.delete_instance_groups()
                self.delete_health_checks()
                self.delete_backend_services()
                raise BackendServiceErr(err)


    def create(self):
        ''' add backend-services resources '''
        try:
            print 'creating instance group'
            self.create_instance_groups()
            print 'adding instance to instance group'
            self.add_instances_to_ig()
            print 'Creating health check'
            self.create_health_checks()
            print 'Creating backkend service'
            self.create_backend_services()
            print 'adding backend service for the instance group'
            self.add_backend_to_services()
        except BackendServiceErr as err:
            reason = str(err)
            print reason
            self.logger.info(reason)
            raise


    def delete_instance_groups(self):
        ''' delete instance-groups '''
        cmd = 'gcloud compute instance-groups unmanaged delete {} ' + \
              '--zone {} --format json --quiet'
        cmd = cmd.format(self.ig_name, self.zone)
        self.logger.info(cmd)
        try:
            result = run_os_command(cmd)
            self.logger.info(result)
        except RunOsCommandsErr as err:
            self.logger.info(str(err))
            self.del_status += str(err)


    def remove_instances_from_ig(self):
        ''' del instance to instance-groups '''
        cmd = 'gcloud compute instance-groups unmanaged ' + \
              'remove-instances {} ' + \
              '--zone {} --instances {} --format json --quiet'
        cmd = cmd.format(self.ig_name,
                         self.zone,
                         self.instance_name)
        self.logger.info(cmd)
        try:
            result = run_os_command(cmd)
            self.logger.info(result)
        except RunOsCommandsErr as err:
            self.logger.info(str(err))
            self.del_status += str(err)


    def delete_health_checks(self):
        ''' add health-checks '''
        cmd = 'gcloud compute https-health-checks delete {} ' + \
              ' --format json --quiet'
        cmd = cmd.format(self.health_name)
        self.logger.info(cmd)
        try:
            result = run_os_command(cmd)
            self.logger.info(result)
        except RunOsCommandsErr as err:
            self.logger.info(str(err))
            self.del_status += str(err)


    def delete_backend_services(self):
        ''' delete backend-services '''
        cmd = 'gcloud compute backend-services delete {} ' + \
                '--format json --quiet'
        cmd = cmd.format(self.svc_name)
        self.logger.info(cmd)
        try:
            result = run_os_command(cmd)
            self.logger.info(result)
        except RunOsCommandsErr as err:
            self.logger.info(str(err))
            self.del_status += str(err)


    def remove_backend_from_services(self):
        ''' remove backend to backend-services '''
        cmd = 'gcloud compute backend-services remove-backend {} ' + \
              '--instance-group {} ' + \
              '--zone {} --format json --quiet'
        cmd = cmd.format(self.svc_name,
                         self.ig_name,
                         self.zone)
        self.logger.info(cmd)
        try:
            result = run_os_command(cmd)
            self.logger.info(result)
        except RunOsCommandsErr as err:
            self.logger.info(str(err))
            self.del_status += str(err)


    def remove(self):
        ''' remove backend-services resources '''
        print 'removing backend from service..'
        self.remove_backend_from_services()
        print 'deleting backend service ..'
        self.delete_backend_services()
        print 'removing instance from instance group..'
        self.remove_instances_from_ig()
        print 'removing instance group..'
        self.delete_instance_groups()
        print 'deleting health check..'
        self.delete_health_checks()
        print 'Done cleaning..'
        if self.del_status:
            self.logger.info(self.del_status)
            raise BackendServiceErr(self.del_status)


    def st_instance(self, option):
        ''' stop or start a  instance '''
        if option not in ['start', 'stop']:
            raise BackendServiceErr('Wrong option:' + option)
        cmd = 'gcloud compute instances {} {} --zone {}' + \
                ' --format json --quiet'
        cmd = cmd.format(option, self.instance_name, self.zone)
        self.logger.info(cmd)
        try:
            result = run_os_command(cmd)
            self.logger.info(result)
        except RunOsCommandsErr as err:
            reason = 'Instance {} failed. Reason:{}'.format(option, str(err))
            self.logger.error(reason)
            raise BackendServiceErr(reason)


    def _get_backend_status(self):
        '''
        get status for backend-services return False when healthState
        Explicitly is UNHEALTHY else True
        '''
        cmd = 'gcloud compute backend-services get-health {} ' + \
              ' --format json'
        cmd = cmd.format(self.svc_name)
        try:
            result = run_os_command(cmd)
        except RunOsCommandsErr:
            raise BackendServiceErr('command run error')
        if not result:
            raise BackendServiceErr('result None')
        try:
            health = json.loads(result)
        except ValueError:
            raise BackendServiceErr('json loads error')
        try:
            status = health[0].get('status')
        except (AttributeError, IndexError):
            raise BackendServiceErr('Backend health IndexError')
        if not status:
            raise BackendServiceErr('status KeyError. Service is not fully up')
        health_status = status.get('healthStatus')
        if not health_status:
            raise BackendServiceErr('healthStatus KeyError. Service is not fully up')
        try:
            health_state = health_status[0].get('healthState')
        except (AttributeError, IndexError):
            raise BackendServiceErr('healthState IndexError. Service is not fully up')
        if not health_state:
            raise BackendServiceErr('health state KeyError. Service is not fully up')
        if health_state == 'UNHEALTHY':
            print 'Reported as Unhealthy'
            return False
        if health_state == 'HEALTHY':
            self.was_helathy = True
            print 'Reported as Healthy'
            return True


    def get_health(self):
        ''' get health. Assume healthy on exception case '''
        try:
            return self._get_backend_status()
        except BackendServiceErr as err:
            self.logger.info(str(err))
            print str(err)
            return True


def run_os_command(cmd):
    '''
    runs a command via the shell and returns the exit code and the
    output result fro the given cmd. raise exception RunOsCommandsErr
    on non exit status and log the errors. return result of exec on sucess
    '''
    spro = subprocess.Popen([cmd], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True, bufsize=-1)
    result, error = spro.communicate()
    returncode = spro.returncode
    if returncode == 0:
        return result
    elif returncode == 1:
        reason = 'Command NOT succeed. Exit code:1. '
    else:
        reason = 'Command error occured. Exit code:{}.'.format(returncode)
    error_msg = 'Command:"{}" FAILed.'.format(cmd)
    err = '{} Reason:{} Error: {} Return:{}'.format(error_msg,
                                                    reason, error, result)
    raise RunOsCommandsErr(err)


def set_service_account(project, path_to_key=None):
    '''
    Activate service account for the given project with path_to_key
    '''
    logger = logging.getLogger('backend')
    if not os.path.exists(path_to_key):
        logger.info('project JSON key-file not found')
        return False
    cmd = 'gcloud auth activate-service-account --key-file "{}" --format json'.\
             format(path_to_key)
    try:
        run_os_command(cmd)
    except RunOsCommandsErr as err:
        msg = 'Unable to auth activate-service-account{}'.format(project)
        logger.info(msg)
        logger.error(err)
        return False
    else:
        return True


def init_logging():
    ''' init logger for this module '''
    logger = logging.getLogger('backend')
    logger.setLevel(logging.INFO)
    filename = 'backend.log'
    hdr = logging.FileHandler(filename)
    fmt = logging.Formatter("%(levelname)s %(asctime)s %(module)s %(funcName)s %(lineno)d %(message)s")
    hdr.setFormatter(fmt)
    logger.addHandler(hdr)
    return logger


def poll(instance_bs):
    ''' do polling on health check '''
    while True:
        if instance_bs.get_health():
            time.sleep(POLL_TIME)
            continue
        try:
            print 'A Unhealthy state is reported. Analyzing more'
            if instance_bs.was_helathy:
                print 'A failure is detected. Stopping the instance'
                instance_bs.st_instance('stop')
            else:
                print 'instance was never reported as healthy'
        except BackendServiceErr as err:
            print 'Stop itself failed.....'
            print str(err)
            break
        time.sleep(2*POLL_TIME)
        print 'Instance stopped'
        instance_bs.was_helathy = False
        try:
            print 'Starting the instance.'
            instance_bs.st_instance('start')
            print 'Restarted the instance waiting for it to mature.'
        except BackendServiceErr as err:
            print 'Start failed.....'
            print str(err)
            break
        time.sleep(2*POLL_TIME)
        print 'Instance started'
    try:
        instance_bs.remove()
    except BackendServiceErr as err:
        print str(err)


def main(args):
    ''' create health check and poll the backend for the status '''
    try:
        instance_bs = BackendService(args.instance_name,
                                     args.zone,
                                     args.path_to_cert)
    except BackendServiceErr as err:
        print str(err)
    else:
        try:
            instance_bs.create()
        except BackendServiceErr as err:
            print 'Backend service creation failed'
            print str(err)
        else:
            msg = 'Polling started. ' + \
                  'Note that it takes some time to setup the backend service'
            print msg
            time.sleep(2*POLL_TIME)
            try:
                poll(instance_bs)
            except KeyboardInterrupt:
                print 'User Keyboard interrupt'
                print 'Cleaning resources.... Please wait'
                try:
                    instance_bs.remove()
                except BackendServiceErr as err:
                    print str(err)

def cli():
    ''' add cli for parameters '''
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('instance_name', help='Name of instance to watch for health check')
    parser.add_argument('zone', help='Compute Engine zone to deploy to.')
    parser.add_argument('path_to_cert',
                        help='Your Google Cloud project credential JSON file path')
    return parser.parse_args()


if __name__ == "__main__":
    init_logging()
    main(cli())
