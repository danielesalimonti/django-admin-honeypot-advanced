=====================
django-admin-honeypot-advanced
=====================



**django-admin-honeypot-advanced** is an honeypot for the Django framework admin page with the following features:

* A first fake login page combined with Hashcash, so that each login attempt requires a proof-of-work that will consume computation resources of attackers.
* A second fake login page again combined with Hashcash and affected by a Blind SQL Injection flaw, the exploitation of which requires enormous computational resources of attackers and would anyhow reveal data from an in-memory database comprising only fake credentials. Additionally, such fake credentials are made of hashed password taken from the famous rockyou list, so to deceive attackers and let them waste more computational resources in the attempt to break such hashes.
* An endpoint affected by path traversal and pointing to a fake filesystem replicating the structure of Docker containers, so to induce attackers to believe the app is running in a misconfigured Docker container exposing sensible files like /etc/passwd and /etc/shadow. Such credential files contain password hashes that may deceive attackers and waste their computational resources.
* A custom 404 page that returns the HTTP status code 200 and include random invisible content, so that non-existent URIs are associated with less predictable pages in the aim to make URIs bruteforcing harder.

The honeypot is a fork of Derek Payton's django-admin-honeypot


**Author**: Daniele Salimonti

**Version**: 1.1.0

**License**: MIT


Documentation
=============


tl;dr
-----

* Install django-admin-honeypot from PyPI::

        pip install django-admin-honeypot-advanced

* Add ``admin_honeypot`` to ``INSTALLED_APPS``
* Update your urls.py:

    ::

        urlpatterns = [
            ...
            path('admin/', include('admin_honeypot.urls', namespace='admin_honeypot')),
            path('secret/', admin.site.urls),
        ]

        handler404 = 'admin_honeypot.views.handler404'

* Run ``python manage.py migrate``

NOTE: replace ``secret`` in the url above with your own secret url prefix
