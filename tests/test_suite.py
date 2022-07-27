import re
from http import HTTPStatus

from urllib.parse import quote_plus

import django
import pytest

from django.test import TestCase
from django.urls import reverse

from admin_honeypot.models import LoginAttempt


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

    def test_create_login_attempt(self):
        """
        A new LoginAttempt object is created
        """
        data = {
            'username': 'admin',
            'password': 'letmein'
        }
        req = self.client.post(self.honeypot_login_url, data)
        print(req.status_code)
        attempt = LoginAttempt.objects.latest('pk')
        self.assertEqual(data['username'], attempt.username)
        self.assertEqual(data['username'], str(attempt))


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
        self.assertIn('Invalid hashcash', str(req.content))

    def test_random_404_page(self):
        """
        unesistent page must be of random size and return 200 as http status
        """
        req1 = self.client.get('/random_page')
        req2 = self.client.get('/random_page2')

        self.assertEqual(req1.status_code, HTTPStatus.OK)
        self.assertEqual(req2.status_code, HTTPStatus.OK)
        self.assertNotEqual(len(req1.content), len(req2.content))
