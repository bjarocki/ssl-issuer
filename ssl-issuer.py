#!/usr/bin/env python3

from datetime import datetime
from hashlib import md5
from pydisque.client import Client
import argparse
import base64
import dns.resolver
import json
import logging
import OpenSSL.crypto
import os
import requests
import shlex
import socket
import subprocess
import sys
import yaml


class Queue:
    def __init__(self, configuration):
        self.client = None
        self.configuration = configuration
        self.queues_list = configuration.get('queues')

    def load_job(self, job):
        try:
            return json.loads(job.decode('UTF-8'))
        except Exception as e:
            print(e)
            return None

    def add_job(self, queue, job, timeout):
        self.__connect()
        try:
            return self.client.add_job(queue, json.dumps(job), timeout=timeout)
        except Exception as e:
            print(e)
            return None

    def __resolve_srv(self, service):
        try:
            first_guy = dns.resolver.query(service, 'srv')
            address = socket.gethostbyname(first_guy.response.answer[0].items[0].target.to_text())
            port = first_guy.response.answer[0].items[0].port
            return address, port
        except:
            return None, None

    def __connect(self):
        connect_address = self.configuration.get('connect')
        if not connect_address and self.configuration.get('connect_discover'):
            host, port = self.__resolve_srv(self.configuration.get('connect_discover'))
            connect_address = ['{0}:{1}'.format(host, port)]

        logging.debug(' CONNECTING TO DISQUE {}'.format(connect_address))
        self.client = Client(connect_address)
        self.client.connect()

    def consume(self):
        self.__connect()
        while True:
            jobs = self.client.get_job(self.queues_list)
            for queue_name, job_id, rawjob in jobs:
                job = self.load_job(rawjob)
                yield (job_id, job)

    def ack_job(self, job_id):
        self.client.ack_job(job_id)


class LE:
    def __init__(self, configuration):
        self.configuration = configuration

    def needs_renew(self, domain):
        filepath = self.ssl_certificate_path(domain)

        if not os.path.isfile(filepath):
            return True

        with open(filepath) as fp:
            certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, fp.read())

        not_after = datetime.strptime(certificate.get_notAfter().decode('UTF-8'), "%Y%m%d%H%M%SZ")
        expire_in = not_after - datetime.now()

        return int(self.configuration.get('ssl_renew_days')) >= expire_in.days

    def ssl_certificate_path(self, domain):
        return self.configuration.get('ssl_certificate_file_pattern').format(domain=domain, storage_path=self.configuration.get('storage_path'))

    def ssl_key_path(self, domain):
        return self.configuration.get('ssl_key_file_pattern').format(domain=domain, storage_path=self.configuration.get('storage_path'))

    def get_ssl_certificate(self, domain):
        filepath = self.ssl_certificate_path(domain)

        if not os.path.isfile(filepath):
            return None

        with open(filepath) as fp:
            return fp.read()

    def get_ssl_key(self, domain):
        filepath = self.ssl_key_path(domain)

        if not os.path.isfile(filepath):
            return None

        with open(filepath) as fp:
            return fp.read()

    def issue(self, domain):
        try:
            command = self.configuration.get('command_pattern').format(domain=domain, email=self.configuration.get('email'), storage_path=self.configuration.get('storage_path'))

            if not self.needs_renew(domain):
                return False, self.get_ssl_certificate(domain), self.get_ssl_key(domain)

            process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, env=self.configuration.get('environment'))

            if not process:
                return True, None, None

            process.wait(int(self.configuration.get('command_timeout') or 180))

            if process.returncode:
                return True, None, None

            return False, self.get_ssl_certificate(domain), self.get_ssl_key(domain)

        except Exception as e:
            return e, None, None


class ConsulKV:
    def __init__(self, configuration):
        self.configuration = configuration

    def __extract_value(self, response):
        try:
            if response.status_code != 200:
                return response.status_code, None

            for row in response.json():
                return None, base64.b64decode(row.get('Value')).decode('UTF-8')

        except Exception as e:
            return str(e), None

    def __key_to_path(self, key):
        return self.configuration.get('key_pattern').format(key=key)

    def get(self, key):
        r = requests.get('{0}{1}'.format(self.configuration.get('consul_addr'), self.__key_to_path(key)))
        return self.__extract_value(r)

    def set(self, key, value):
        r = requests.put('{0}{1}'.format(self.configuration.get('consul_addr'), self.__key_to_path(key)), data=value)

        if r.status_code != 200:
            return r.status_code
        else:
            return None

    def calculate_hash(self, value):
        return md5(bytes(value.encode('UTF-8'))).hexdigest()

    def in_sync(self, value, stored_value):
        if not stored_value:
            return False

        if self.calculate_hash(value) != self.calculate_hash(stored_value):
            return False

        return True


class SSLWorker:
    def __init__(self, configuration_file):
        self.configuration_file = configuration_file

    def main(self):
        with open(self.configuration_file, 'r') as fp:
            try:
                configuration = yaml.load(fp)
            except yaml.YAMLError as e:
                print(e)
                sys.exit(1)

        logging.basicConfig(level=getattr(logging, configuration['logging'].get('level').upper()))

        letsencrypt = LE(configuration['issuer'].get('letsencrypt'))
        queue = Queue(configuration['queuing'].get('disque'))
        storage = ConsulKV(configuration['storage'].get('consul'))

        for job_id, job in queue.consume():
            logging.debug('NEW JOB {0} [{1}]'.format(job_id, job))
            job_failed = False
            for domain in job.get('domains'):
                logging.debug(' WORKING WITH {}'.format(domain))
                error, certificate, key = letsencrypt.issue(domain)

                if error:
                    job_failed = True
                    logging.warning(' ISSUER ERROR {}'.format(error))
                    continue

                if not certificate or not key:
                    logging.warning(' ISSUER KEY/CERTIFICATE EMPTY RESPONSE FOR DOMAIN {}'.format(domain))
                    continue

                error, stored_key = storage.get('{}/key'.format(domain))

                if error or not storage.in_sync(key, stored_key):
                    storage.set('{}/key'.format(domain), key)
                    logging.debug(' {} KEY HAS BEEN UPDATED.'.format(domain))
                else:
                    logging.debug(' {} KEY FILE IN SYNC.'.format(domain))

                error, stored_certificate = storage.get('{}/certificate'.format(domain))

                if error or not storage.in_sync(certificate, stored_certificate):
                    storage.set('{}/certificate'.format(domain), certificate)
                    logging.debug(' {} CERTIFICATE HAS BEEN UPDATED.'.format(domain))
                else:
                    logging.debug(' {} CERTIFICATE FILE IN SYNC.'.format(domain))

            if not job_failed:
                queue.ack_job(job_id)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This guy let us use letsencrypt in a unblocking manner.')
    parser.add_argument('-c', '--config-file', help='Configuration file.', required=True)
    subparsers = parser.add_subparsers()
    parse_consul_template_client = subparsers.add_parser('consul-template-client', help='Run in consul-template-client mode.', add_help=False)
    parse_consul_template_client.add_argument('-s', '--services-list', help='File containing a list of services generated by consul-template.', required=True)
    parse_consul_template_client.set_defaults(action='consul-template-client')
    parser_issuer = subparsers.add_parser('issuer', help='Run in issuer mode.', add_help=False)
    parser_issuer.set_defaults(action='issuer')
    args = parser.parse_args()

    if args.action == 'consul-template-client':
        with open(args.config_file, 'r') as fp:
            try:
                configuration = yaml.load(fp)
            except yaml.YAMLError as e:
                print(e)
                sys.exit(1)

        queue = Queue(configuration['queuing'].get('disque'))

        domains = []
        domain_template = configuration['consul_template_client'].get('domain_template') or '{domain}'

        with open(args.services_list) as fp:
            for line in fp.readlines():
                if line.rstrip():
                    domains.append(domain_template.format(domain=line.rstrip()))

        job_id = queue.add_job(queue.queues_list[0], {'domains': domains}, 3000)
        if job_id:
            print(json.dumps({'status': 200, 'info': 'successfully added job with id: {}'.format(job_id.decode('UTF-8'))}))

    elif args.action == 'issuer':
        sslworker = SSLWorker(args.config_file)
        sslworker.main()
