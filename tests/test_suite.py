import hashlib
import os
import random
import re
from http import HTTPStatus
from math import floor
from time import strftime, time, gmtime

import json

from django.test import TestCase
from django.urls import reverse

from admin_honeypot.models import LoginAttempt, Preferences
from string import ascii_letters


class AdminHoneypotTest(TestCase):
    maxDiff = None

    @property
    def admin_login_url(self):
        return reverse('admin:login')

    @property
    def admin_url(self):
        return reverse('admin:index')

    @property
    def honeypot_login_url(self):
        return reverse('admin_honeypot:login')

    @property
    def honeypot_url(self):
        return reverse('admin_honeypot:index')

    @property
    def honeypot_login_sqli_url(self):
        return reverse('admin_honeypot:login_sqli')

    @property
    def honeypot_path_traversal_url(self):
        return reverse('admin_honeypot:path_traversal')

    @property
    def honeypot_hashcash_metadata_url(self):
        return reverse('admin_honeypot:hashcash_metadata')

    def test_create_login_attempt(self):
        """
        A new LoginAttempt object is created
        """
        data = {
            'username': 'admin',
            'password': 'letmein'
        }
        req = self.client.post(self.honeypot_login_url, data)
        attempt = LoginAttempt.objects.latest('pk')
        self.assertEqual(data['username'], attempt.username)
        self.assertEqual(data['username'], str(attempt))

    def test_login_with_hashcash_calculation(self):

        username = 'user'
        password = 'password'
        hashcash_metadata_req = self.client.get(self.honeypot_hashcash_metadata_url)
        hashcash_metadata = json.loads(hashcash_metadata_req.content.decode('utf-8'))
        hashcash_stamp = self.calculate_hashcash_stamp(username, password,
                                                       bits=int(hashcash_metadata['bits']),
                                                       salt=hashcash_metadata['salt'])
        data = {
            'username': username,
            'password': password,
            'hashcash_stamp': hashcash_stamp
        }
        req = self.client.post(self.honeypot_login_url, data)
        attempt = LoginAttempt.objects.latest('pk')
        self.assertEqual(data['username'], attempt.username)
        self.assertEqual(data['username'], str(attempt))
        self.assertEqual(data['hashcash_stamp'], attempt.hashcash_stamp)

    def test_trailing_slash(self):
        """
        /admin redirects to /admin/ permanent redirect.
        """
        url = self.honeypot_url + 'foo/'
        redirect_url = self.honeypot_login_url + '?next=' + url

        response = self.client.get(url.rstrip('/'), follow=True)
        self.assertRedirects(response, redirect_url, status_code=301)

    def test_real_url_leak(self):
        """
        A test to make sure the real admin URL isn't leaked in the honeypot
        login form page.
        """

        honeypot_html = self.client.get(self.honeypot_url, follow=True).content.decode('utf-8')
        self.assertNotIn('{0}'.format(self.admin_url), honeypot_html)
        self.assertNotIn('{0}'.format(self.admin_login_url), honeypot_html)

    def test_random_hashcash(self):
        """
        test with an invalid random string as hashcash
        """
        data = {
            'username': 'admin',
            'password': 'letmein',
            'hashcash_stamp': 'aswdscvwevwe1233'
        }
        req = self.client.post(self.honeypot_login_url, data)
        self.assertIn('Invalid hashcash', str(req.content))

    def test_empty_hashcash(self):
        """
        test with an empty hashcash
        """
        data = {
            'username': 'admin',
            'password': 'letmein',
        }
        req = self.client.post(self.honeypot_login_url, data)
        self.assertIn('Invalid hashcash', req.content.decode('utf-8'))

    def test_outdated_hashcash_stamp(self):
        preferences = Preferences.objects.first()
        timestamp = strftime("%y%m%d%H%M%S", gmtime(time() - (preferences.hashcash_validity_in_minutes * 60 + 60)))
        # generated a minutes before his validity

        username = 'user'
        password = 'password'
        hashcash_metadata_req = self.client.get(self.honeypot_hashcash_metadata_url)
        hashcash_metadata = json.loads(hashcash_metadata_req.content.decode('utf-8'))
        hashcash_stamp = self.calculate_hashcash_stamp(username, password,
                                                       bits=int(hashcash_metadata['bits']),
                                                       salt=hashcash_metadata['salt'],
                                                       timestamp=timestamp)
        data = {
            'username': username,
            'password': password,
            'hashcash_stamp': hashcash_stamp
        }

        req = self.client.post(self.honeypot_login_url, data)
        self.assertIn('Invalid hashcash', req.content.decode('utf-8'))

    def test_wrong_bits_hashcash_stamp(self):
        preferences = Preferences.objects.first()

        username = 'user'
        password = 'password'
        hashcash_metadata_req = self.client.get(self.honeypot_hashcash_metadata_url)
        hashcash_metadata = json.loads(hashcash_metadata_req.content.decode('utf-8'))
        hashcash_stamp = self.calculate_hashcash_stamp(username, password,
                                                       bits=int(hashcash_metadata['bits']) - 1,
                                                       salt=hashcash_metadata['salt'], )
        data = {
            'username': username,
            'password': password,
            'hashcash_stamp': hashcash_stamp
        }

        req = self.client.post(self.honeypot_login_url, data)
        self.assertIn('Invalid hashcash', req.content.decode('utf-8'))

    def test_wrong_salt_hashcash_stamp(self):

        username = 'user'
        password = 'password'
        hashcash_metadata_req = self.client.get(self.honeypot_hashcash_metadata_url)
        hashcash_metadata = json.loads(hashcash_metadata_req.content.decode('utf-8'))
        hashcash_stamp = self.calculate_hashcash_stamp(username, password,
                                                       bits=int(hashcash_metadata['bits']),
                                                       salt='wrong_salt')
        data = {
            'username': username,
            'password': password,
            'hashcash_stamp': hashcash_stamp
        }

        req = self.client.post(self.honeypot_login_url, data)
        self.assertIn('Invalid hashcash', req.content.decode('utf-8'))

    def test_wrong_resource_hashcash_stamp(self):

        username = 'user'
        password = 'password'
        hashcash_metadata_req = self.client.get(self.honeypot_hashcash_metadata_url)
        hashcash_metadata = json.loads(hashcash_metadata_req.content.decode('utf-8'))
        hashcash_stamp = self.calculate_hashcash_stamp('wrong_user', 'wrong_pass',
                                                       bits=int(hashcash_metadata['bits']),
                                                       salt='wrong_salt')
        data = {
            'username': username,
            'password': password,
            'hashcash_stamp': hashcash_stamp
        }

        req = self.client.post(self.honeypot_login_url, data)
        self.assertIn('Invalid hashcash', req.content.decode('utf-8'))

    def test_random_404_page(self):

        req1 = self.client.get('/random_page')
        req2 = self.client.get('/random_page2')

        self.assertEqual(req1.status_code, HTTPStatus.OK)
        self.assertEqual(req2.status_code, HTTPStatus.OK)
        self.assertNotEqual(len(req1.content), len(req2.content))

    def test_blind_sqli_login(self):
        username = "' or 1=1 --"
        password = 'garbage'
        hashcash = self.calculate_hashcash_stamp(username, password)
        data = {
            'username': username,
            'password': password,
            'hashcash_stamp': hashcash
        }

        req = self.client.post(self.honeypot_login_sqli_url, data)

        self.assertIn('Incorrect password', req.content.decode('utf-8'))

    def test_blind_sqli_login_wrong_hashcash(self):
        username = "' or 1=1 --"
        password = 'garbage'
        hashcash = 'random_wrong_hashcash'
        data = {
            'username': username,
            'password': password,
            'hashcash_stamp': hashcash
        }

        req = self.client.post(self.honeypot_login_sqli_url, data)

        self.assertIn('Invalid hashcash', req.content.decode('utf-8'))

    def calculate_hashcash_stamp(self, username, password, bits=20, salt=None, timestamp=None):
        alphabet = ascii_letters + "+/="
        if salt is None:
            salt = ''.join([random.choice(alphabet) for _ in [None] * 6])

        if timestamp is None:
            timestamp = strftime("%y%m%d%H%M%S", gmtime(time()))

        challenge = f'1:{bits}:{timestamp}:{username}@{password}::{salt}:'

        non_zero_binary_to_hex = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111']
        non_zero_to_find = []
        counter = 0
        zero_hex_digits = int(floor(bits / 4.))
        zeros = '0' * zero_hex_digits
        if bits % 4 != 0:
            for _bin in non_zero_binary_to_hex:
                if '0' * (bits % 4) == _bin[:(bits % 4)]:
                    non_zero_to_find.append(str(non_zero_binary_to_hex.index(_bin)))
        while 1:
            digest = hashlib.sha1((challenge + hex(counter)[2:]).encode()).hexdigest()
            if digest[:zero_hex_digits] == zeros:
                if bits % 4 == 0:
                    return challenge + hex(counter)[2:]
                else:
                    if digest[bits % 4] in non_zero_to_find:
                        return challenge + hex(counter)[2:]
            counter += 1

    def test_path_traversal(self):

        req_etc_passwd = self.client.get(self.honeypot_path_traversal_url + '?file=/etc/passwd')
        path = os.path.dirname(__file__).replace('tests', 'admin_honeypot') + '/fake_fs/etc/passwd'
        etc_passwd = open(path)
        data = etc_passwd.read()
        etc_passwd.close()
        content = req_etc_passwd.content.decode('utf-8').replace('\r\n', '\n')
        self.assertEqual(content, data)

    def test_path_traversal_nonexistent_file(self):

        req_etc_passwd = self.client.get(self.honeypot_path_traversal_url + '?file=random_file')
        self.assertIn('not found', req_etc_passwd.content.decode('utf-8'))
