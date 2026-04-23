from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sentinel', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='securitypolicy',
            name='category',
            field=models.CharField(
                choices=[
                    ('MALICIOUS_CODE', 'Malicious Code'),
                    ('DATA_EXFILTRATION', 'Data Exfiltration'),
                    ('OBFUSCATION', 'Obfuscation'),
                    ('WEAPONS', 'Weapons'),
                    ('NETWORK_ACCESS', 'Network Access'),
                    ('PROMPT_INJECTION', 'Prompt Injection'),
                    ('POLICY_VIOLATION', 'Policy Violation'),
                ],
                max_length=32,
            ),
        ),
        migrations.AlterField(
            model_name='threatdetail',
            name='category',
            field=models.CharField(
                choices=[
                    ('MALICIOUS_CODE', 'Malicious Code'),
                    ('DATA_EXFILTRATION', 'Data Exfiltration'),
                    ('OBFUSCATION', 'Obfuscation'),
                    ('WEAPONS', 'Weapons'),
                    ('NETWORK_ACCESS', 'Network Access'),
                    ('PROMPT_INJECTION', 'Prompt Injection'),
                    ('POLICY_VIOLATION', 'Policy Violation'),
                ],
                max_length=32,
            ),
        ),
    ]
