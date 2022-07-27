import hashlib
import os
from math import floor

import django
from django import forms
from django.contrib.admin.forms import AdminAuthenticationForm
from time import strftime, localtime, time, gmtime

from django.core.exceptions import ObjectDoesNotExist
from ipware import get_client_ip

from admin_honeypot.models import HashcashMetadata, Preferences
from django.utils.translation import gettext_lazy as _
from csvkit.utilities.csvsql import CSVSQL
from contextlib import redirect_stdout
import io


class HoneypotLoginForm(AdminAuthenticationForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_messages["invalid_hashcash"] = _("Invalid hashcash.")

    def clean(self):
        """
        Always raise the default error message, because we don't
        care what they entered here.
        """
        print("clean")
        if self.check_hashcash_stamp():
            print("OK HASHCASH")
            raise forms.ValidationError(
                self.error_messages['invalid_login'],
                code='invalid_login',
                params={'username': self.username_field.verbose_name}
            )
        else:
            print("INVALID HASHCASH")
            raise forms.ValidationError(
                self.error_messages['invalid_hashcash'],
                code='invalid_hashcash',
            )

    def check_hashcash_stamp(self):
        ip_address, is_rouable = get_client_ip(self.request)
        hashcash_stamp = self.request.POST.get('hashcash_stamp')
        if hashcash_stamp is None:
            return False
        resource = self.request.POST.get('username') + '@' + self.request.POST.get('password')
        preferences = Preferences.objects.all().first()
        if preferences is not None:
            good_until = strftime("%y%m%d%H%M%S", gmtime(time() - (preferences.hashcash_validity_in_minutes * 60)))
        else:
            good_until = strftime("%y%m%d%H%M%S", gmtime(time() - 300))  # 300 = 5 minutes
        try:
            claim, date, res, ext, rand, counter = hashcash_stamp[2:].split(':')
        except ValueError:
            # ERR.write("Malformed version 1 hashcash stamp!\n")
            return False
        try:
            hashcash_metadata = HashcashMetadata.objects.get(ip_address=ip_address, salt=rand, is_used=False)
        except ObjectDoesNotExist:
            return False
        if hashcash_metadata is None:
            return False
        hashcash_metadata.is_used = True
        hashcash_metadata.save()
        if resource is not None and resource != res:
            return False
        elif hashcash_metadata.bits != int(claim):
            return False
        elif date < good_until:
            return False
        else:
            non_zero_binary_to_hex = ['0000', '0001', '0010', '0011', '0100', '0101', '0110', '0111']
            non_zero_to_find = []
            zero_hex_digits = int(floor(int(claim) / 4))
            if int(claim) % 4 != 0:
                for _bin in non_zero_binary_to_hex:
                    if '0' * (int(claim) % 4) == _bin[:(int(claim) % 4)]:
                        non_zero_to_find.append(str(non_zero_binary_to_hex.index(_bin)))
            digest = hashlib.sha1(hashcash_stamp.encode()).hexdigest()
            return digest.startswith('0' * zero_hex_digits) if int(claim) % 4 == 0 else digest.startswith(
                '0' * zero_hex_digits) and digest[int(claim) % 4] in non_zero_to_find


class HoneypotLoginFormSQLi(AdminAuthenticationForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_messages['invalid_hashcash'] = _('Invalid hashcash.')
        self.error_messages['incorrect_password'] = _('Incorrect password, note that the field is case sensitive.')

    def clean(self):

        query = ['--query', "select * from users where username= '" + self.request.POST.get("username") + "'",
                 os.path.join(os.path.dirname(__file__), 'fakedb/users.csv')]

        out = io.StringIO()
        with redirect_stdout(out):
            result = CSVSQL(query)
            result.main()
        s = out.getvalue().splitlines()
        print(s)

        if self.check_hashcash_stamp():
            print("OK HASHCASH")
            if len(s) >= 2:
                print(s[1])
                raise forms.ValidationError(
                    self.error_messages['incorrect_password'],
                    code='incorrect_password',
                )
            else:
                print("NO ANSWER")
                raise forms.ValidationError(
                    self.error_messages['invalid_login'],
                    code='invalid_login',
                    params={'username': self.username_field.verbose_name}
                )
        else:
            print("INVALID HASHCASH")
            raise forms.ValidationError(
                self.error_messages['invalid_hashcash'],
                code='invalid_hashcash',
            )

    def check_hashcash_stamp(self):
        hashcash_stamp = self.request.POST.get('hashcash_stamp')
        if hashcash_stamp is None:
            return False
        resource = self.request.POST.get('username') + '@' + self.request.POST.get('password')
        good_until = strftime("%y%m%d%H%M%S", gmtime(time() - 60))  # 60 = 1 minute
        try:
            claim, date, res, ext, rand, counter = hashcash_stamp[2:].split(':')
        except ValueError:
            return False
        bits = 20
        if resource is not None and resource != res:
            return False
        elif bits != int(claim):
            return False
        elif date < good_until:
            return False
        else:
            zero_hex_digits = int(floor(int(claim) / 4))
            digest = hashlib.sha1(hashcash_stamp.encode()).hexdigest()
            return digest.startswith('0' * zero_hex_digits) if int(claim) % 4 == 0 else digest.startswith(
                '0' * zero_hex_digits)
