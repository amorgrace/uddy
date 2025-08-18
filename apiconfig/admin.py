from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Product
from .forms import ProductAdminForm
from django.utils.timesince import timesince

# Custom User Admin
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    model = User
    list_display = ('id', 'email', 'fullname', 'phone_number', 'country', 'is_staff', 'is_active')
    search_fields = ('email', 'fullname', 'phone_number', 'country')
    ordering = ('email',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('fullname', 'phone_number', 'country')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'is_superuser', 'groups', 'user_permissions')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'fullname', 'phone_number', 'country', 'password1', 'password2', 'is_staff', 'is_active')}
        ),
    )


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    form = ProductAdminForm
    list_display = ('id', 'title', 'category', 'price', 'time_ago')
    list_filter = ('category', 'created_at')
    search_fields = ('title', 'category')
    ordering = ('-created_at',)
    readonly_fields = ('image_url',)

    def time_ago(self, obj):
        return f"{timesince(obj.created_at)} ago"
    time_ago.short_description = 'Created'
    time_ago.admin_order_field = 'created_at'

