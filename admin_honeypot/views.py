import os
from importlib.metadata import files

import django
import fs.errors
from django.http import JsonResponse, HttpResponse
from django.template.loader import render_to_string

from ipware import get_client_ip

from admin_honeypot.forms import HoneypotLoginForm, HoneypotLoginFormSQLi
from admin_honeypot.models import LoginAttempt, HashcashMetadata, Preferences, FakeUser
from admin_honeypot.signals import honeypot

from django.contrib.admin.sites import AdminSite
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.views import redirect_to_login
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views import generic
import random
from string import ascii_letters
from base64 import b64encode
from fs.osfs import OSFS


class AdminHoneypot(generic.FormView):
    template_name = 'admin_honeypot/login.html'
    form_class = HoneypotLoginForm

    def dispatch(self, request, *args, **kwargs):
        if not request.path.endswith('/'):
            return redirect(request.path + '/', permanent=True)

        # Django redirects the user to an explicit login view with
        # a next parameter, so emulate that.
        login_url = reverse('admin_honeypot:login')
        if request.path != login_url:
            return redirect_to_login(request.get_full_path(), login_url)

        return super(AdminHoneypot, self).dispatch(request, *args, **kwargs)

    def get_form(self, form_class=form_class):
        return form_class(self.request, **self.get_form_kwargs())

    def get_context_data(self, **kwargs):

        context = super(AdminHoneypot, self).get_context_data(**kwargs)
        context.update({
            **AdminSite().each_context(self.request),
            'app_path': self.request.get_full_path(),
            REDIRECT_FIELD_NAME: reverse('admin_honeypot:index'),
            'title': _('Log in'),
        })
        return context

    def form_valid(self, form):
        return self.form_invalid(form)

    def form_invalid(self, form):

        ip_address, is_routable = get_client_ip(self.request)
        instance = LoginAttempt.objects.create(
            username=self.request.POST.get('username'),
            session_key=self.request.session.session_key,
            ip_address=ip_address,
            user_agent=self.request.META.get('HTTP_USER_AGENT'),
            path=self.request.get_full_path(),
            hashcash_stamp=self.request.POST.get('hashcash_stamp')
        )

        honeypot.send(sender=LoginAttempt, instance=instance, request=self.request)
        preferences = Preferences.objects.all().first()
        if preferences is not None and preferences.has_fail2ban_log:
            log = open("honeypot.log")
            log.write(str(ip_address) + '\n')
            log.close()

        return super(AdminHoneypot, self).form_invalid(form)


class AdminHoneypotSQLi(generic.FormView):
    template_name = 'admin_honeypot/login2.html'
    form_class = HoneypotLoginFormSQLi

    def dispatch(self, request, *args, **kwargs):
        if not request.path.endswith('/'):
            return redirect(request.path + '/', permanent=True)
        # Django redirects the user to an explicit login view with
        # a next parameter, so emulate that.
        # login_url = reverse('admin_honeypot:login_sqli')
        # if request.path != login_url:
        #     return redirect_to_login(request.get_full_path(), login_url)
        users_csv = open(str(os.path.join(os.path.dirname(__file__) + '/fakedb/users.csv')), 'w')
        users_csv.write('ID;username;password;salt\n')
        for user in FakeUser.objects.all():
            users_csv.write(user.print_for_csv() + '\n')
        users_csv.close()

        return super(AdminHoneypotSQLi, self).dispatch(request, *args, **kwargs)

    def get_form(self, form_class=form_class):
        return form_class(self.request, **self.get_form_kwargs())

    def get_context_data(self, **kwargs):
        context = super(AdminHoneypotSQLi, self).get_context_data(**kwargs)
        context.update({
            **AdminSite().each_context(self.request),
            'app_path': self.request.get_full_path(),
            REDIRECT_FIELD_NAME: reverse('admin_honeypot:index'),
            'title': _('Log in'),
        })
        return context

    def form_valid(self, form):
        return self.form_invalid(form)

    def form_invalid(self, form):

        ip_address, is_routable = get_client_ip(self.request)
        instance = LoginAttempt.objects.create(
            username=self.request.POST.get('username'),
            session_key=self.request.session.session_key,
            ip_address=ip_address,
            user_agent=self.request.META.get('HTTP_USER_AGENT'),
            path=self.request.get_full_path(),
            hashcash_stamp=self.request.POST.get('hashcash_stamp')
        )
        honeypot.send(sender=LoginAttempt, instance=instance, request=self.request)

        preferences = Preferences.objects.all().first()
        if preferences is not None and preferences.has_fail2ban_log:
            log = open("honeypot.log")
            log.write(str(ip_address) + '\n')
            log.close()

        return super(AdminHoneypotSQLi, self).form_invalid(form)


class PathTraversal(generic.detail.BaseDetailView):

    def dispatch(self, request, *args, **kwargs):
        if not request.path.endswith('/'):
            return redirect(request.path + '/', permanent=True)

        # Django redirects the user to an explicit login view with
        # a next parameter, so emulate that.
        # login_url = reverse('admin_honeypot:login_sqli')
        # if request.path != login_url:
        #     return redirect_to_login(request.get_full_path(), login_url)

        return super(PathTraversal, self).dispatch(request, *args, **kwargs)

    def generate_in_memory_fs(self):

        file_to_get = self.request.GET.get('file')
        filesys = OSFS(os.path.join(os.path.dirname(__file__)) + '/fake_fs')
        try:
            file = filesys.readtext(file_to_get)
            return file
        except fs.errors.ResourceNotFound as error:
            return error
        finally:
            filesys.tree()
            # print(filesys)
            filesys.close()

    def get(self, request, *args, **kwargs):
        file = self.generate_in_memory_fs()
        return HttpResponse(file, content_type='text/plain; charset=utf8')


def hashcash_metadata(request):
    preferences = Preferences.objects.all().first()
    data = {}
    if preferences is not None:
        length = preferences.salt_length
        alphabet = ascii_letters + "+/="
        salt = ''.join([random.choice(alphabet) for _ in [None] * length])

        ip_address, is_rouable = get_client_ip(request)
        attempts_number = HashcashMetadata.objects.filter(ip_address=ip_address).count()
        bits = preferences.bits_to_increase * attempts_number + preferences.bits_to_increase
        data = {'salt': salt, 'bits': bits}
        HashcashMetadata.objects.create(
            ip_address=ip_address,
            salt=salt,
            bits=bits,
            is_used=False
        )
    return JsonResponse(data)


def handler404(request, exception=None, template_name='admin_honeypot/404.html'):
    alphabet = ascii_letters + "+/="
    length = random.randint(1000, 1000000)
    random_space = random.randint(1, 200)
    variable = ''.join([random.choice(alphabet) for _ in [None] * length])
    title = ''.join([random.choice(alphabet) for _ in [None] * 7])
    hint = b64encode(reverse('admin_honeypot:login').encode('ascii'))
    response = HttpResponse(render_to_string(template_name,
                                             {'variable': variable,
                                              'hint': hint.decode('ascii'),
                                              'title': title,
                                              'random_space': ' '*random_space}))
    response.status_code = 200

    return response
