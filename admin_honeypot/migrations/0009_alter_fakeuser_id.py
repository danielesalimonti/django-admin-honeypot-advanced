# Generated by Django 4.0.4 on 2022-06-06 14:50

from django.db import migrations, models


class Migration(migrations.Migration):

    def create_default_fake_users(apps, _):
        FakeUser = apps.get_model('admin_honeypot', 'FakeUser')
        FakeUser.objects.create(username='marcus',
                                password='$argon2i$v=19$m=65536,t=5,p=8$b3p1bUtkbWxvTzFEOVpqNQ$7qeeHz8PaCDtdRGzEuxt1YOeg7IzRAK4FMUgUxuSXiM',
                                salt='ozumKdmloO1D9Zj5')
        FakeUser.objects.create(username='maria',
                                password='$argon2i$v=19$m=65536,t=5,p=8$ZGx1dFNDUUJLNlZDeDRxag$24gZfgY1M/ryNtDU//QQnEzWJ1suGJxVb9959YLT1UE',
                                salt='dlutSCQBK6VCx4qj')
        FakeUser.objects.create(username='orazio',
                                password='$argon2i$v=19$m=65536,t=5,p=8$SWFudFNKRVRBTXlqM3hncg$yRUnUoE7l6ifhZL225xTJPkm5st/I0+uhG+TmJ6c8B8',
                                salt='IantSJETAMyj3xgr')
        FakeUser.objects.create(username='george',
                                password='$argon2i$v=19$m=65536,t=5,p=8$YmtTRzNhZUljUUVneURzbQ$t4p6WF9bQ6CNO4HzoY361vDXWiEEvl7MNWkQxLwi85k',
                                salt='bkSG3aeIcQEgyDsm')
        FakeUser.objects.create(username='dylan',
                                password='$argon2i$v=19$m=65536,t=5,p=8$amxxWHV4clFYeFljb1hOMw$2IPBxyzMXTDUBF4fk/QKpZHPGiKlxi8vNY6C2JSdAao',
                                salt='jlqXuxrQXxYcoXN3')
        FakeUser.objects.create(username='sanna',
                                password='$argon2i$v=19$m=65536,t=5,p=8$cnRtWFZ2d2VzeDNoTW1RSw$/jCS/ObVtugflIjqUcnAzv4AmlSIVxTOxQ/mvP0+Y+o',
                                salt='rtmXVvwesx3hMmQK')
        FakeUser.objects.create(username='dev',
                                password='$argon2i$v=19$m=65536,t=5,p=8$WXdmWThaa25sUWdYMlJZdg$xHH2Y6qZ22BGFR78p/SmnVHCzGXLPFrqDthsQfNVac4',
                                salt='YwfY8ZknlQgX2RYv')

    dependencies = [
        ('admin_honeypot', '0008_fakeuser'),
    ]

    operations = [
        migrations.AlterField(
            model_name='fakeuser',
            name='ID',
            field=models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.RunPython(create_default_fake_users)
    ]
