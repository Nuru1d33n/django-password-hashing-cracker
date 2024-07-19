from django.contrib import admin
from passwords.models import (
    Password, MD5Password, SHA1Password, SHA224Password,
    SHA256Password, SHA384Password, SHA512Password, SHA3256Password
)

@admin.register(Password)
class PasswordAdmin(admin.ModelAdmin):
    list_display = ('value',)
    search_fields = ('value',)

@admin.register(MD5Password)
class MD5PasswordAdmin(admin.ModelAdmin):
    list_display = ('value',)
    search_fields = ('value',)

@admin.register(SHA1Password)
class SHA1PasswordAdmin(admin.ModelAdmin):
    list_display = ('value',)
    search_fields = ('value',)

@admin.register(SHA224Password)
class SHA224PasswordAdmin(admin.ModelAdmin):
    list_display = ('value',)
    search_fields = ('value',)

@admin.register(SHA256Password)
class SHA256PasswordAdmin(admin.ModelAdmin):
    list_display = ('value',)
    search_fields = ('value',)

@admin.register(SHA384Password)
class SHA384PasswordAdmin(admin.ModelAdmin):
    list_display = ('value',)
    search_fields = ('value',)

@admin.register(SHA512Password)
class SHA512PasswordAdmin(admin.ModelAdmin):
    list_display = ('value',)
    search_fields = ('value',)

@admin.register(SHA3256Password)
class SHA3256PasswordAdmin(admin.ModelAdmin):
    list_display = ('value',)
    search_fields = ('value',)
