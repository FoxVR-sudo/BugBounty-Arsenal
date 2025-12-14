"""
Management command to create/update subscription plans
"""
from django.core.management.base import BaseCommand
from subscriptions.models import Plan


class Command(BaseCommand):
    help = 'Create or update subscription plans with correct settings'

    def handle(self, *args, **options):
        plans_data = [
            {
                'name': 'FREE',
                'display_name': 'Free',
                'description': 'Perfect for getting started with basic security scanning',
                'price': 0.00,
                'scans_per_day': 3,
                'scans_per_month': 50,
                'concurrent_scans': 1,
                'max_urls_per_scan': 10,
                'storage_limit_mb': 100,  # 100 MB
                'retention_days': 7,  # 7 days
                'max_detectors': 15,
                'allowed_scan_types': ['web', 'api'],
                'features': [
                    '3 scans per day',
                    '50 scans per month',
                    '15 basic detectors',
                    '100 MB storage',
                    '7 days retention',
                    'Web & API scanning',
                    'HTML reports',
                ],
                'is_popular': False,
                'order': 1,
            },
            {
                'name': 'BASIC',
                'display_name': 'Basic',
                'description': 'For individuals and small teams needing more scanning capacity',
                'price': 29.00,
                'scans_per_day': 10,
                'scans_per_month': 200,
                'concurrent_scans': 2,
                'max_urls_per_scan': 50,
                'storage_limit_mb': 500,  # 500 MB
                'retention_days': 30,  # 30 days
                'max_detectors': 25,
                'allowed_scan_types': ['web', 'api', 'vulnerability'],
                'features': [
                    '10 scans per day',
                    '200 scans per month',
                    '25 detectors',
                    '500 MB storage',
                    '30 days retention',
                    'Web, API & Vulnerability scanning',
                    'PDF & HTML reports',
                    'Email notifications',
                ],
                'is_popular': False,
                'order': 2,
            },
            {
                'name': 'PRO',
                'display_name': 'Professional',
                'description': 'For professionals requiring comprehensive security testing',
                'price': 99.00,
                'scans_per_day': 50,
                'scans_per_month': 1000,
                'concurrent_scans': 5,
                'max_urls_per_scan': 200,
                'storage_limit_mb': 2048,  # 2 GB
                'retention_days': 90,  # 90 days
                'max_detectors': -1,  # All detectors
                'allowed_scan_types': ['web', 'api', 'vulnerability', 'mobile', 'custom'],
                'features': [
                    '50 scans per day',
                    '1,000 scans per month',
                    'All 39 detectors',
                    '2 GB storage',
                    '90 days retention',
                    'All scan types',
                    'PDF, HTML, JSON, CSV reports',
                    'Priority email support',
                    'API access',
                    'Custom scan configurations',
                ],
                'is_popular': True,
                'order': 3,
            },
            {
                'name': 'ENTERPRISE',
                'display_name': 'Enterprise',
                'description': 'For large organizations with unlimited scanning needs',
                'price': 299.00,
                'scans_per_day': -1,  # Unlimited
                'scans_per_month': -1,  # Unlimited
                'concurrent_scans': 10,
                'max_urls_per_scan': 1000,
                'storage_limit_mb': 10240,  # 10 GB
                'retention_days': 365,  # 1 year
                'max_detectors': -1,  # All detectors
                'allowed_scan_types': ['web', 'api', 'vulnerability', 'mobile', 'custom'],
                'features': [
                    'Unlimited scans',
                    '10 concurrent scans',
                    'All 39 detectors',
                    '10 GB storage',
                    '1 year retention',
                    'All scan types',
                    'All export formats',
                    'Priority support 24/7',
                    'Dedicated account manager',
                    'Custom integrations',
                    'SLA guarantees',
                    'White-label reports',
                ],
                'is_popular': False,
                'order': 4,
            },
        ]

        for plan_data in plans_data:
            plan, created = Plan.objects.update_or_create(
                name=plan_data['name'],
                defaults=plan_data
            )
            
            action = 'Created' if created else 'Updated'
            self.stdout.write(
                self.style.SUCCESS(f'{action} plan: {plan.display_name} (${plan.price}/month)')
            )

        self.stdout.write(self.style.SUCCESS('\n✅ All plans configured successfully!'))
