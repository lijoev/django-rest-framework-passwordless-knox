import logging
from rest_framework import parsers, renderers, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated 
from rest_framework.views import APIView
from knoxpasswordlessdrf.settings import api_settings
from knox.models import AuthTokenManager, AuthToken
from knoxpasswordlessdrf.serializers import (
    EmailAuthSerializer,
    MobileAuthSerializer,
    CallbackTokenAuthSerializer,
    CallbackTokenVerificationSerializer,
    EmailVerificationSerializer,
    MobileVerificationSerializer,
)
from knoxpasswordlessdrf.services import TokenService
from knoxpasswordlessdrf.services import TokenService
from knox.settings import knox_settings
from rest_framework.serializers import DateTimeField
from django.utils import timezone
from django.contrib.auth.signals import user_logged_in, user_logged_out

logger = logging.getLogger(__name__)


class AbstractBaseObtainCallbackToken(APIView):
    """
    This returns a 6-digit callback token we can trade for a user's Auth Token.
    """
    success_response = "A login token has been sent to you."
    failure_response = "Unable to send you a login code. Try again later."

    message_payload = {}

    @property
    def serializer_class(self):
        # Our serializer depending on type
        raise NotImplementedError

    @property
    def alias_type(self):
        # Alias Type
        raise NotImplementedError

    def post(self, request, *args, **kwargs):
        if self.alias_type.upper() not in api_settings.PASSWORDLESS_AUTH_TYPES:
            # Only allow auth types allowed in settings.
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            # Validate -
            user = serializer.validated_data['user']
            # Create and send callback token
            success = TokenService.send_token(user, self.alias_type, **self.message_payload)

            # Respond With Success Or Failure of Sent
            if success:
                status_code = status.HTTP_200_OK
                response_detail = self.success_response
            else:
                status_code = status.HTTP_400_BAD_REQUEST
                response_detail = self.failure_response
            return Response({'detail': response_detail}, status=status_code)
        else:
            return Response(serializer.error_messages, status=status.HTTP_400_BAD_REQUEST)


class ObtainEmailCallbackToken(AbstractBaseObtainCallbackToken):
    permission_classes = (AllowAny,)
    serializer_class = EmailAuthSerializer
    success_response = "A login token has been sent to your email."
    failure_response = "Unable to email you a login code. Try again later."

    alias_type = 'email'

    email_subject = api_settings.PASSWORDLESS_EMAIL_SUBJECT
    email_plaintext = api_settings.PASSWORDLESS_EMAIL_PLAINTEXT_MESSAGE
    email_html = api_settings.PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE_NAME
    message_payload = {'email_subject': email_subject,
                       'email_plaintext': email_plaintext,
                       'email_html': email_html}


class ObtainMobileCallbackToken(AbstractBaseObtainCallbackToken):
    permission_classes = (AllowAny,)
    serializer_class = MobileAuthSerializer
    success_response = "We texted you a login code."
    failure_response = "Unable to send you a login code. Try again later."

    alias_type = 'mobile'

    mobile_message = api_settings.PASSWORDLESS_MOBILE_MESSAGE
    message_payload = {'mobile_message': mobile_message}


class ObtainEmailVerificationCallbackToken(AbstractBaseObtainCallbackToken):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailVerificationSerializer
    success_response = "A verification token has been sent to your email."
    failure_response = "Unable to email you a verification code. Try again later."

    alias_type = 'email'

    email_subject = api_settings.PASSWORDLESS_EMAIL_VERIFICATION_SUBJECT
    email_plaintext = api_settings.PASSWORDLESS_EMAIL_VERIFICATION_PLAINTEXT_MESSAGE
    email_html = api_settings.PASSWORDLESS_EMAIL_VERIFICATION_TOKEN_HTML_TEMPLATE_NAME
    message_payload = {
        'email_subject': email_subject,
        'email_plaintext': email_plaintext,
        'email_html': email_html
    }


class ObtainMobileVerificationCallbackToken(AbstractBaseObtainCallbackToken):
    permission_classes = (IsAuthenticated,)
    serializer_class = MobileVerificationSerializer
    success_response = "We texted you a verification code."
    failure_response = "Unable to send you a verification code. Try again later."

    alias_type = 'mobile'

    mobile_message = api_settings.PASSWORDLESS_MOBILE_MESSAGE
    message_payload = {'mobile_message': mobile_message}


class AbstractBaseObtainAuthToken(APIView):
    """
    This is a duplicate of rest_framework's own ObtainAuthToken method.
    Instead, this returns an Auth Token based on our 6 digit callback token and source.
    """
    serializer_class = None

    def get_context(self):
        return {'request': self.request, 'format': self.format_kwarg, 'view': self}

    def get_token_ttl(self):
        return knox_settings.TOKEN_TTL

    def get_token_limit_per_user(self):
        return knox_settings.TOKEN_LIMIT_PER_USER

    def get_user_serializer_class(self):
        return knox_settings.USER_SERIALIZER

    def get_expiry_datetime_format(self):
        return knox_settings.EXPIRY_DATETIME_FORMAT

    def format_expiry_datetime(self, expiry):
        datetime_format = self.get_expiry_datetime_format()
        return DateTimeField(format=datetime_format).to_representation(expiry)

    def get_post_response_data(self, user, token, instance):
        UserSerializer = self.get_user_serializer_class()

        data = {
            'expiry': self.format_expiry_datetime(instance.expiry),
            'token': token
        }
        if UserSerializer is not None:
            data["user"] = UserSerializer(
                user,
                context=self.get_context()
            ).data
        return data

    def post(self, request, format=None):
        token_limit_per_user = self.get_token_limit_per_user()
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data['user']
            if token_limit_per_user is not None:
                now = timezone.now()
                token = user.auth_token_set.filter(expiry__gt=now)
                if token.count() >= token_limit_per_user:
                    return Response(
                        {"error": "Maximum amount of tokens allowed per user exceeded."},
                        status=status.HTTP_403_FORBIDDEN
                    )
            token_ttl = self.get_token_ttl()
            instance, token = AuthToken.objects.create(user, token_ttl)
            user_logged_in.send(sender=user.__class__,
                                request=request, user=user)
            data = self.get_post_response_data(user, token, instance)
            return Response(data)


class ObtainAuthTokenFromCallbackToken(AbstractBaseObtainAuthToken):
    """
    This is a duplicate of rest_framework's own ObtainAuthToken method.
    Instead, this returns an Auth Token based on our callback token and source.
    """
    permission_classes = (AllowAny,)
    serializer_class = CallbackTokenAuthSerializer


class VerifyAliasFromCallbackToken(APIView):
    """
    This verifies an alias on correct callback token entry using the same logic as auth.
    Should be refactored at some point.
    """
    serializer_class = CallbackTokenVerificationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'user_id': self.request.user.id})
        if serializer.is_valid(raise_exception=True):
            return Response({'detail': 'Alias verified.'}, status=status.HTTP_200_OK)
        else:
            logger.error("Couldn't verify unknown user. Errors on serializer: {}".format(serializer.error_messages))

        return Response({'detail': 'We couldn\'t verify this alias. Try again later.'}, status.HTTP_400_BAD_REQUEST)
