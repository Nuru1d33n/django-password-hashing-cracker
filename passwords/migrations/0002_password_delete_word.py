# Generated by Django 4.2.14 on 2024-07-18 20:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('passwords', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Password',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(max_length=4444)),
            ],
        ),
        migrations.DeleteModel(
            name='Word',
        ),
    ]
