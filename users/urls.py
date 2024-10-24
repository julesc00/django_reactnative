from django.urls import path

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import (
    TestView,
    UserView,
    UserLoginView,
    UserVerificationView
)

app_name = "users"

urlpatterns = [
    path("test", TestView.as_view()),
    path("create-user/", UserView.as_view()),
    path("get-user", UserLoginView.as_view()),
    path("login-user/", UserLoginView.as_view()),
    path("verify-user/<str:pk>", UserVerificationView.as_view()),
]
