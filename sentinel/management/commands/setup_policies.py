"""
Management command: python manage.py setup_policies
Seeds the default security policies into the database.
"""
from django.core.management.base import BaseCommand
from sentinel.models import SecurityPolicy


DEFAULT_POLICIES = [
    {
        'name': 'Malicious Code Detection',
        'category': 'MALICIOUS_CODE',
        'severity': 'CRITICAL',
        'auto_kill': True,
        'description': 'Detects reverse shells, exploits, malware scripts, and other harmful code patterns.',
    },
    {
        'name': 'Data Exfiltration Prevention',
        'category': 'DATA_EXFILTRATION',
        'severity': 'CRITICAL',
        'auto_kill': True,
        'description': 'Prevents leakage of credentials, API keys, database dumps, and sensitive files.',
    },
    {
        'name': 'Weapons Information Filter',
        'category': 'WEAPONS',
        'severity': 'HIGH',
        'auto_kill': False,
        'description': 'Blocks discussion of explosive devices, chemical/biological weapons, and WMDs.',
    },
    {
        'name': 'Unauthorized Network Access',
        'category': 'NETWORK_ACCESS',
        'severity': 'HIGH',
        'auto_kill': True,
        'description': 'Prevents AI from generating code that makes external network connections.',
    },
    {
        'name': 'Prompt Injection Detection',
        'category': 'PROMPT_INJECTION',
        'severity': 'MEDIUM',
        'auto_kill': False,
        'description': 'Detects attempts to override AI guidelines or jailbreak the model.',
    },
    {
        'name': 'Policy Violation Monitor',
        'category': 'POLICY_VIOLATION',
        'severity': 'LOW',
        'auto_kill': False,
        'description': 'Flags references to classified or restricted information.',
    },
]


class Command(BaseCommand):
    help = 'Seed the database with default security policies.'

    def handle(self, *args, **kwargs):
        created = 0
        updated = 0
        for policy_data in DEFAULT_POLICIES:
            obj, was_created = SecurityPolicy.objects.update_or_create(
                name=policy_data['name'],
                defaults={
                    'category': policy_data['category'],
                    'severity': policy_data['severity'],
                    'auto_kill': policy_data['auto_kill'],
                    'description': policy_data['description'],
                    'is_active': True,
                    'updated_by': 'setup_policies',
                }
            )
            if was_created:
                created += 1
                self.stdout.write(self.style.SUCCESS(f"  Created: {obj.name}"))
            else:
                updated += 1
                self.stdout.write(f"  Updated: {obj.name}")

        self.stdout.write(self.style.SUCCESS(
            f"\n✅ Done. {created} policies created, {updated} updated."
        ))
