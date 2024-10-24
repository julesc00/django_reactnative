import hashlib
from uuid import uuid4

from django.contrib.auth import authenticate, get_user_model
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from users.models import Token
from users.serializers import UserSerializer, TokenSerializer


User = get_user_model()


class TestView(APIView):

    def get(self, request, format=None):
        print("[INFO] API was called")
        return Response("[INFO] You made it", status=status.HTTP_200_OK)


class UserView(APIView):

    def post(self, request, format=None):
        print("[INFO] Creating a user")

        user_data = request.data
        user_data["is_active"] = False
        user_serializer = UserSerializer(data=user_data)

        if user_serializer.is_valid(raise_exception=False):
            user_serializer.save()

            # Generate a token
            salt = uuid4().hex
            hash_obj = hashlib.sha256(salt.encode() + str(user_serializer.data["id"]).encode())
            token = f"{hash_obj.hexdigest()}:{salt}"

            token_serializer = TokenSerializer(data={
                "user": user_serializer.data["id"],
                "token": token
            })
            if token_serializer.is_valid(raise_exception=False):
                token_serializer.save()

                # Send email logic here (commented out in your code)
                """
                message = Mail(
                    from_email="tim@poieo-dev.com",
                    to_emails=user_data['email'],
                    subject='Please Confirm your Email Address',
                    html_content=f"Hi {user_data['first_name']},<br><br>Thank you for signing up. To confirm your email address, please click <a href='http://localhost:8000/api/v1.0/user/verify-user/{token}'>HERE</a>"
                )
                try:
                    sg = SendGridAPIClient("<<SENDGRID API KEY>>")
                    response = sg.send(message)
                except Exception as e:
                    print("ERROR", e)
                    return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                """

                return Response({"user": user_serializer.data}, status=status.HTTP_200_OK)

            else:
                return Response({"error": token_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        else:
            return Response({"error": user_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class UserVerificationView(APIView):

    def get(self, request, pk, format=None):
        print(f"[INFO] Verifying user: {pk}")

        token_obj = Token.objects.filter(token=pk).first()
        user = User.objects.filter(id=token_obj.user.id).first()

        if user:
            user_serializer = UserSerializer(user, data={"is_active": True}, partial=True)
            if user_serializer.is_valid(raise_exception=False):
                user_serializer.save()

                return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_404_NOT_FOUND)


class UserLoginView(APIView):
    # Convert a user token into data
    def get(self, request, format=None):
        if request.user.is_authenticated == False or request.user.is_active == False:
            return Response("[INFO] Invalid Credentials", status=status.HTTP_403_FORBIDDEN)

        user = UserSerializer(request.user)
        return Response(user.data, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        print("[INFO] Login class")

        user_obj = User.objects.filter(
            email=request.data["username"].first() or User.objects.filter(username=request.data["username"]).first()
        )

        if user_obj is not None:
            credentials = {
                "username": user_obj.username,
                "password": request.data["password"]
            }
            user = authenticate(**credentials)

            if user and user.is_active:
                user_serializer = UserSerializer(user)
                return Response(user_serializer.data, status=status.HTTP_200_OK)
        return Response("[WARNING] Invalid credentials", status=status.HTTP_403_FORBIDDEN)

