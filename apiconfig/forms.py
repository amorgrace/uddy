from django import forms
from .models import Product
import cloudinary.uploader

class ProductAdminForm(forms.ModelForm):
    upload_image = forms.ImageField(required=False, help_text="Upload product image")

    class Meta:
        model = Product
        fields = ['title', 'category', 'price', 'image_url', 'upload_image']  # include upload_image for admin use

    def save(self, commit=True):
        instance = super().save(commit=False)

        upload = self.cleaned_data.get('upload_image')
        if upload:
            result = cloudinary.uploader.upload(upload)
            instance.image_url = result['secure_url']  # Save Cloudinary URL

        if commit:
            instance.save()
        return instance
