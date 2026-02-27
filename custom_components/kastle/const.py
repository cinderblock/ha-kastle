"""Constants for the Kastle Access integration."""

DOMAIN = "kastle"

BASE_URL = "https://mykastle.com/KastleSDK/api"

# This is a static app-level API key, not a user secret.
# It is hardcoded in the Kastle SDK APK at:
#   com.kastle.kastlesdk.services.api.common.KSServiceConstants
#     .REQUEST_HEADER_REQUEST_TOKEN_VALUE
# Every copy of the Kastle Presence app ships with this same value.
REQUEST_TOKEN = "B7A6A1F06D8A48BE826BBD184D0BBE17F224C661DABBD9B581ADAA7F2D56A375"

# User-Agent string matching the iOS Kastle Presence app (v7.2.0.7).
# Sent on every API call so the server treats requests as coming from the real app.
USER_AGENT = "convergedapp-ios/7.2.0.7 CFNetwork/3860.400.51 Darwin/25.3.0"

# Application GUID from the iOS app, sent during ValidateIdentity to identify the app.
APPLICATION_GUID = "28c66592-ba40-4a00-a11d-46ded00457d3"

# .NET epoch offset: ticks between 0001-01-01 and 1970-01-01
DOTNET_EPOCH_OFFSET = 621355968000000000

# Kastle API error codes
ERR_SIGNATURE_FAILURE = 10001
ERR_NO_SIGNATURE = 10002
ERR_NONCE_EXPIRED = 10003
ERR_NOT_REGISTERED = 60134
