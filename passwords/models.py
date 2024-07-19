from django.db import models

class Password(models.Model):
    value = models.CharField(max_length=4444)

    def __str__(self):
        return self.value

class MD5Password(models.Model):
    value = models.CharField(max_length=32)
    original_password = models.ForeignKey(Password, on_delete=models.CASCADE)

    def __str__(self):
        return self.value

class SHA1Password(models.Model):
    value = models.CharField(max_length=40)
    original_password = models.ForeignKey(Password, on_delete=models.CASCADE)

    def __str__(self):
        return self.value

class SHA224Password(models.Model):
    value = models.CharField(max_length=56)
    original_password = models.ForeignKey(Password, on_delete=models.CASCADE)

    def __str__(self):
        return self.value

class SHA256Password(models.Model):
    value = models.CharField(max_length=64)
    original_password = models.ForeignKey(Password, on_delete=models.CASCADE)

    def __str__(self):
        return self.value

class SHA384Password(models.Model):
    value = models.CharField(max_length=96)
    original_password = models.ForeignKey(Password, on_delete=models.CASCADE)

    def __str__(self):
        return self.value

class SHA512Password(models.Model):
    value = models.CharField(max_length=128)
    original_password = models.ForeignKey(Password, on_delete=models.CASCADE)

    def __str__(self):
        return self.value

class SHA3256Password(models.Model):
    value = models.CharField(max_length=64)
    original_password = models.ForeignKey(Password, on_delete=models.CASCADE)

    def __str__(self):
        return self.value
