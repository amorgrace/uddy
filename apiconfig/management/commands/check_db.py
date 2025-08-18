from django.core.management.base import BaseCommand
from django.db import connection


class Command(BaseCommand):
    help = "Check database connection"

    def handle(self, *args, **kwargs):
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1;")
                self.stdout.write(self.style.SUCCESS("✅ Database connection OK"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Database connection failed: {e}"))
