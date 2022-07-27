from django.db import models
from django.utils.translation import gettext_lazy as _


class LoginAttempt(models.Model):
    username = models.CharField(_("username"), max_length=255, blank=True, null=True)
    ip_address = models.GenericIPAddressField(_("ip address"), protocol='both', blank=True, null=True)
    session_key = models.CharField(_("session key"), max_length=50, blank=True, null=True)
    user_agent = models.TextField(_("user-agent"), blank=True, null=True)
    timestamp = models.DateTimeField(_("timestamp"), auto_now_add=True)
    path = models.TextField(_("path"), blank=True, null=True)

    hashcash_stamp = models.CharField(_("hashcash stamp"), max_length=255, null=True, blank=True)

    class Meta:
        verbose_name = _("login attempt")
        verbose_name_plural = _("login attempts")
        ordering = ('timestamp',)

    def __str__(self):
        return self.username


class HashcashMetadata(models.Model):
    ip_address = models.GenericIPAddressField(_("ip address"), protocol='both', blank=True, null=True)
    is_used = models.BooleanField(_("is used"))
    salt = models.CharField(_("salt"), max_length=255)
    bits = models.IntegerField(_("bits"))

    def __str__(self):
        return self.ip_address + "-" + self.salt


class Preferences(models.Model):
    has_fail2ban_log = models.BooleanField(_("fail2ban log"))
    bits_to_increase = models.IntegerField(_("bits to increase"))
    salt_length = models.IntegerField(_("salt length"))
    hashcash_validity_in_minutes = models.IntegerField("hashcash validity in minutes")

    class Meta:
        verbose_name_plural = _("preferences")

    def __str__(self):
        return "Preferences"


class FakeUser(models.Model):
    ID = models.AutoField("ID", auto_created=True, primary_key=True)
    username = models.CharField(_("username"), max_length=255)
    password = models.TextField(_("password"))
    salt = models.CharField(_("salt"), max_length=255)

    def __str__(self):
        return self.username

    def print_for_csv(self):
        return str(self.ID) + ';' + self.username + ';' + self.password + ';' + self.salt
