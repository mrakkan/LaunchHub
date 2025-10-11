from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0011_drop_allauth_tables'),
    ]

    operations = [
        migrations.AddField(
            model_name='project',
            name='container_port',
            field=models.IntegerField(default=80),
        ),
    ]